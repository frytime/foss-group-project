"""
Byzantine Fault Tolerance - PBFT-style normal case (National Audit Log, Intelligence Distribution).

"Trust the protocol, not the participants":
  * every message is Ed25519-signed and verified against a fixed membership registry
  * a PRE-PREPARE must come from the view's primary and its digest must match the payload
  * an honest replica accepts at most one digest per (view, sequence)
  * prepared   = matching PRE-PREPARE + 2f+1 PREPAREs from distinct validators
  * committed  = prepared + 2f+1 COMMITs from distinct validators
Byzantine validators are not run by this code; experiments script their behaviour
using the validator's (or a stolen) private key and inject messages directly.
View change is not implemented, so a stalled sequence stays stalled (liveness gap).
"""
import hashlib
import json
from collections import deque
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Callable, Optional

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric import ed25519


class MessageType(Enum):
    PRE_PREPARE = "pre_prepare"
    PREPARE = "prepare"
    COMMIT = "commit"


@dataclass
class BFTMessage:
    msg_type: MessageType
    view: int
    sequence: int
    digest: str
    sender: str
    signature: bytes
    payload: Any = None
    epoch: int = 0
    extra: dict = field(default_factory=dict)   # e.g. self-presented public key, epoch certificate

    def signed_bytes(self) -> bytes:
        return f"{self.msg_type.value}|{self.view}|{self.sequence}|{self.digest}|{self.epoch}".encode()


@dataclass
class Validator:
    validator_id: str
    private_key: ed25519.Ed25519PrivateKey
    byzantine: bool = False
    # honest replica state
    accepted_pp: dict = field(default_factory=dict)      # (view, seq) -> digest
    payloads: dict = field(default_factory=dict)         # digest -> payload
    prepares: dict = field(default_factory=dict)         # (view, seq, digest) -> set(sender)
    commits: dict = field(default_factory=dict)
    prepared: set = field(default_factory=set)
    committed: dict = field(default_factory=dict)        # seq -> (digest, payload)

    @property
    def public_key(self):
        return self.private_key.public_key()


def digest_of(payload: Any) -> str:
    return hashlib.sha256(json.dumps(payload, sort_keys=True).encode()).hexdigest()[:16]


def _noop_log(node, view, event, detail):
    pass


class BFTCluster:
    def __init__(self, n: int = 4, byzantine: tuple = (), open_membership: bool = False,
                 log: Callable[[str, int, str, dict], None] = _noop_log):
        self.n = n
        self.f = (n - 1) // 3
        self.quorum_size = 2 * self.f + 1
        self.validators: dict[str, Validator] = {}
        for i in range(n):
            vid = f"V{i}"
            self.validators[vid] = Validator(vid, ed25519.Ed25519PrivateKey.generate(), vid in byzantine)
        self.registry = {vid: v.public_key for vid, v in self.validators.items()}  # fixed membership
        self.open_membership = open_membership
        self.view = 0
        self.next_seq = 1
        self.queue: deque = deque()
        self.log = log
        self.rejections: list[dict] = []

    # -- identity -----------------------------------------------------------------
    def primary(self, view: Optional[int] = None) -> str:
        return f"V{(self.view if view is None else view) % self.n}"

    def honest(self) -> list[Validator]:
        return [v for v in self.validators.values() if not v.byzantine]

    def make_message(self, msg_type, sequence, payload_or_digest, sender, key, view=None, payload=None, **extra):
        """Build and sign a message with an arbitrary key (honest, Byzantine or stolen)."""
        digest = payload_or_digest if isinstance(payload_or_digest, str) else digest_of(payload_or_digest)
        if payload is None and not isinstance(payload_or_digest, str):
            payload = payload_or_digest
        msg = BFTMessage(msg_type, self.view if view is None else view, sequence, digest, sender, b"",
                         payload, epoch=extra.pop("epoch", self.current_epoch()), extra=extra)
        msg.signature = key.sign(msg.signed_bytes())
        return msg

    def current_epoch(self) -> int:
        return 0

    def signing_key(self, v: Validator):
        return v.private_key

    def _sign(self, v: Validator, msg_type, view, seq, digest) -> BFTMessage:
        msg = BFTMessage(msg_type, view, seq, digest, v.validator_id, b"", epoch=self.current_epoch())
        msg.signature = self.signing_key(v).sign(msg.signed_bytes())
        return msg

    def public_key_for(self, msg: BFTMessage):
        pub = self.registry.get(msg.sender)
        if pub is None and self.open_membership:
            pub = msg.extra.get("public_key")       # Sybil: identity is whatever key you present
        return pub

    def verify(self, receiver: Validator, msg: BFTMessage) -> Optional[str]:
        """Return None if valid, else a rejection reason."""
        pub = self.public_key_for(msg)
        if pub is None:
            return "unknown_validator"
        try:
            pub.verify(msg.signature, msg.signed_bytes())
        except InvalidSignature:
            return "bad_signature"
        if msg.msg_type == MessageType.PRE_PREPARE:
            if msg.sender != self.primary(msg.view):
                return "pre_prepare_not_from_primary"
            if msg.payload is None or digest_of(msg.payload) != msg.digest:
                return "digest_mismatch"
        return None

    # -- message delivery ---------------------------------------------------------
    def send(self, msg: BFTMessage, to: Optional[list[str]] = None):
        for vid in (to or list(self.validators)):
            if vid != msg.sender:
                self.queue.append((vid, msg))

    def run(self):
        while self.queue:
            vid, msg = self.queue.popleft()
            v = self.validators.get(vid)
            if v is not None and not v.byzantine:
                self._deliver(v, msg)

    def _observe(self, receiver: Validator, msg: BFTMessage):
        """Hook for hardening (equivocation detection). Return False to drop the message."""
        return True

    def _deliver(self, v: Validator, msg: BFTMessage):
        reason = self.verify(v, msg)
        if reason:
            self.rejections.append({"at": v.validator_id, "from": msg.sender, "type": msg.msg_type.value,
                                    "reason": reason})
            self.log(v.validator_id, msg.view, "message_rejected",
                     {"from": msg.sender, "type": msg.msg_type.value, "seq": msg.sequence, "reason": reason})
            return
        if self._observe(v, msg) is False:
            return
        key = (msg.view, msg.sequence)
        if msg.msg_type == MessageType.PRE_PREPARE:
            if key in v.accepted_pp:
                if v.accepted_pp[key] != msg.digest:
                    self.log(v.validator_id, msg.view, "conflicting_pre_prepare_ignored",
                             {"seq": msg.sequence, "kept": v.accepted_pp[key], "ignored": msg.digest})
                return
            v.accepted_pp[key] = msg.digest
            v.payloads[msg.digest] = msg.payload
            self._add_vote(v, v.prepares, msg.view, msg.sequence, msg.digest, msg.sender)
            self._add_vote(v, v.prepares, msg.view, msg.sequence, msg.digest, v.validator_id)
            self.send(self._sign(v, MessageType.PREPARE, msg.view, msg.sequence, msg.digest))
        elif msg.msg_type == MessageType.PREPARE:
            self._add_vote(v, v.prepares, msg.view, msg.sequence, msg.digest, msg.sender)
        elif msg.msg_type == MessageType.COMMIT:
            self._add_vote(v, v.commits, msg.view, msg.sequence, msg.digest, msg.sender)
        self._progress(v, msg.view, msg.sequence, msg.digest)

    def _add_vote(self, v, table, view, seq, digest, sender):
        table.setdefault((view, seq, digest), set()).add(sender)

    def _progress(self, v: Validator, view, seq, digest):
        k = (view, seq, digest)
        if (k not in v.prepared and v.accepted_pp.get((view, seq)) == digest
                and len(v.prepares.get(k, ())) >= self.quorum_size):
            v.prepared.add(k)
            self._add_vote(v, v.commits, view, seq, digest, v.validator_id)
            self.send(self._sign(v, MessageType.COMMIT, view, seq, digest))
        if k in v.prepared and seq not in v.committed and len(v.commits.get(k, ())) >= self.quorum_size:
            v.committed[seq] = (digest, v.payloads[digest])
            self.log(v.validator_id, view, "committed",
                     {"seq": seq, "digest": digest, "payload": v.payloads[digest],
                      "commit_votes": sorted(v.commits[k])})

    # -- client API ---------------------------------------------------------------
    def propose(self, payload: Any) -> int:
        """Honest primary proposes payload at the next sequence number. Returns the sequence."""
        seq = self.next_seq
        self.next_seq += 1
        primary = self.validators[self.primary()]
        msg = self.make_message(MessageType.PRE_PREPARE, seq, payload, primary.validator_id,
                                self.signing_key(primary))
        self.log(primary.validator_id, self.view, "pre_prepare", {"seq": seq, "digest": msg.digest})
        if not primary.byzantine:
            self._deliver(primary, msg)       # primary processes its own proposal
        self.send(msg)
        self.run()
        return seq

    def committed_at(self, seq: int) -> dict:
        return {v.validator_id: v.committed[seq][0] for v in self.honest() if seq in v.committed}

    def check_safety(self) -> dict:
        forks = {}
        seqs = {s for v in self.honest() for s in v.committed}
        for s in seqs:
            digests = {v.committed[s][0] for v in self.honest() if s in v.committed}
            if len(digests) > 1:
                forks[s] = sorted(digests)
        return {"forks": forks, "safe": not forks}

    def get_state(self) -> dict:
        return {"n": self.n, "f": self.f, "quorum": self.quorum_size, "view": self.view,
                "byzantine": [v for v, x in self.validators.items() if x.byzantine],
                "committed": {v.validator_id: {s: d for s, (d, _) in v.committed.items()} for v in self.honest()}}


# -- attack helper (used by experiments) -------------------------------------------
def inject_equivocation(c: "BFTCluster", seq: int, payload_a, payload_b, to_a: list, to_b: list,
                        colluders: dict, primary_key) -> tuple:
    """A Byzantine primary sends PRE-PREPARE(payload_a) to to_a and PRE-PREPARE(payload_b) to to_b.
    colluders maps validator_id -> private key the attacker controls (Byzantine, stolen or Sybil);
    each colluder then signs PREPARE and COMMIT for BOTH digests and sends them to everyone.
    Returns (digest_a, digest_b)."""
    prim = c.primary()
    pp_a = c.make_message(MessageType.PRE_PREPARE, seq, payload_a, prim, primary_key)
    pp_b = c.make_message(MessageType.PRE_PREPARE, seq, payload_b, prim, primary_key)
    c.log(prim, c.view, "byzantine_equivocation", {"seq": seq, "digest_a": pp_a.digest, "to_a": to_a,
                                                    "digest_b": pp_b.digest, "to_b": to_b})
    c.send(pp_a, to_a)
    c.send(pp_b, to_b)
    for vid, key in colluders.items():
        extra = {} if vid in c.registry else {"public_key": key.public_key()}
        for d in (pp_a.digest, pp_b.digest):
            for t in (MessageType.PREPARE, MessageType.COMMIT):
                c.send(c.make_message(t, seq, d, vid, key, **extra))
    c.run()
    return pp_a.digest, pp_b.digest
