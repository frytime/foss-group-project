"""
Original Hardening Mechanism (Task B5):
Epoch-scoped validator keys + equivocation-proof revocation + verifiable quorum certificates.

Baseline BFT trusts a validator's single long-lived key. If that key is stolen, the
attacker *is* that validator for ever, and a Byzantine validator that equivocates is
never removed. The hardened cluster changes three things:

 1. Epoch keys. Each validator holds a long-term identity key (kept offline / in an HSM)
    that only signs an epoch certificate for a fresh per-epoch Ed25519 key. Protocol
    messages are signed with the epoch key and carry the epoch number; replicas reject
    messages from any other epoch. A stolen epoch key expires at the next rotation.
 2. Equivocation proofs. Any honest replica that sees two validly signed messages from the
    same validator for the same (view, sequence) with different digests holds a
    self-contained, verifiable proof. The proof is checked and the validator is revoked:
    its keys are rejected and its votes are removed from every uncommitted tally.
 3. Quorum certificates. A commit is exported as 2f+1 epoch-key signatures from distinct,
    non-revoked validators, which an external auditor can verify against the identity keys.

What it does NOT fix: theft of an identity key, or f+1 colluding validators that never
equivocate (they are indistinguishable from honest ones).
"""
from dataclasses import dataclass
from typing import Optional

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519

from nerp.consensus.bft import BFTCluster, BFTMessage, MessageType, Validator


def _raw(pub) -> bytes:
    return pub.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)


@dataclass
class EquivocationProof:
    validator_id: str
    a: BFTMessage
    b: BFTMessage


@dataclass
class QuorumCertificate:
    view: int
    sequence: int
    digest: str
    epoch: int
    signatures: dict   # validator_id -> signature over the COMMIT message


class HardenedBFTCluster(BFTCluster):
    def __init__(self, n: int = 4, byzantine: tuple = (), log=None, **kw):
        kw = {"log": log} if log else {}
        super().__init__(n=n, byzantine=byzantine, **kw)
        # The base registry holds long-term identity keys; they never sign protocol messages.
        self.identity_registry = dict(self.registry)
        self.epoch = 0
        self.epoch_keys: dict[str, ed25519.Ed25519PrivateKey] = {}
        self.epoch_registry: dict[tuple, ed25519.Ed25519PublicKey] = {}
        self.revoked: set[str] = set()
        self.proofs: list[EquivocationProof] = []
        self.seen: dict[tuple, BFTMessage] = {}         # (sender, view, seq) -> first signed message
        self.commit_msgs: dict[tuple, dict] = {}        # (view, seq, digest) -> {sender: msg}
        self.rotations = 0
        self._rotate_all()

    # -- epoch keys -------------------------------------------------------------
    def _rotate_all(self):
        for v in self.validators.values():
            if v.validator_id in self.revoked:
                continue
            key = ed25519.Ed25519PrivateKey.generate()
            cert = v.private_key.sign(self._cert_bytes(v.validator_id, self.epoch, key.public_key()))
            self.register_epoch_key(v.validator_id, self.epoch, key.public_key(), cert)
            self.epoch_keys[v.validator_id] = key

    @staticmethod
    def _cert_bytes(vid, epoch, pub) -> bytes:
        return b"epoch-cert|" + vid.encode() + b"|" + str(epoch).encode() + b"|" + _raw(pub)

    def register_epoch_key(self, vid, epoch, pub, cert) -> bool:
        identity = self.identity_registry.get(vid)
        if identity is None or vid in self.revoked:
            return False
        try:
            identity.verify(cert, self._cert_bytes(vid, epoch, pub))
        except InvalidSignature:
            self.log(vid, self.view, "epoch_cert_rejected", {"epoch": epoch})
            return False
        self.epoch_registry[(vid, epoch)] = pub
        return True

    def advance_epoch(self):
        self.epoch += 1
        self.rotations += 1
        self._rotate_all()
        self.log("cluster", self.view, "epoch_rotated",
                 {"epoch": self.epoch, "active": sorted(set(self.validators) - self.revoked)})

    def current_epoch(self) -> int:
        return self.epoch

    def signing_key(self, v: Validator):
        return self.epoch_keys[v.validator_id]

    # -- verification -----------------------------------------------------------
    def public_key_for(self, msg: BFTMessage):
        return self.epoch_registry.get((msg.sender, msg.epoch))

    def verify(self, receiver, msg: BFTMessage) -> Optional[str]:
        if msg.sender in self.revoked:
            return "revoked_validator"
        if msg.epoch != self.epoch:
            return "stale_epoch"
        return super().verify(receiver, msg)

    def _valid(self, msg: BFTMessage) -> bool:
        pub = self.epoch_registry.get((msg.sender, msg.epoch))
        if pub is None:
            return False
        try:
            pub.verify(msg.signature, msg.signed_bytes())
            return True
        except InvalidSignature:
            return False

    def verify_proof(self, p: EquivocationProof) -> bool:
        a, b = p.a, p.b
        return (a.sender == b.sender == p.validator_id and (a.view, a.sequence) == (b.view, b.sequence)
                and a.digest != b.digest and self._valid(a) and self._valid(b))

    def _observe(self, receiver: Validator, msg: BFTMessage):
        key = (msg.sender, msg.view, msg.sequence)
        first = self.seen.setdefault(key, msg)
        if first.digest != msg.digest:
            proof = EquivocationProof(msg.sender, first, msg)
            if self.verify_proof(proof):
                self.proofs.append(proof)
                self.log(receiver.validator_id, msg.view, "equivocation_proof",
                         {"validator": msg.sender, "seq": msg.sequence,
                          "digests": [first.digest, msg.digest]})
                self.revoke(msg.sender)
                return False
        if msg.msg_type == MessageType.COMMIT:
            self.commit_msgs.setdefault((msg.view, msg.sequence, msg.digest), {})[msg.sender] = msg
        return True

    def revoke(self, vid: str):
        if vid in self.revoked:
            return
        self.revoked.add(vid)
        purged = 0
        for v in self.honest():
            for table in (v.prepares, v.commits):
                for (view, seq, d), voters in table.items():
                    if seq not in v.committed and vid in voters:
                        voters.discard(vid)
                        purged += 1
            if vid == self.primary():
                for (view, seq) in list(v.accepted_pp):
                    if seq not in v.committed:
                        del v.accepted_pp[(view, seq)]
        self.log("cluster", self.view, "validator_revoked", {"validator": vid, "votes_purged": purged})

    # -- quorum certificates -------------------------------------------------------
    def _sign(self, v, msg_type, view, seq, digest):
        msg = super()._sign(v, msg_type, view, seq, digest)
        if msg_type == MessageType.COMMIT:
            self.commit_msgs.setdefault((view, seq, digest), {})[v.validator_id] = msg
        return msg

    def quorum_certificate(self, seq: int) -> Optional[QuorumCertificate]:
        for (view, s, d), msgs in self.commit_msgs.items():
            if s != seq:
                continue
            epoch = next(iter(msgs.values())).epoch
            good = {vid: m.signature for vid, m in msgs.items()
                    if vid not in self.revoked and m.epoch == epoch and self._valid(m)}
            if len(good) >= self.quorum_size:
                return QuorumCertificate(view, seq, d, epoch, good)
        return None

    def verify_quorum_certificate(self, qc: QuorumCertificate) -> bool:
        ok = 0
        for vid, sig in qc.signatures.items():
            if vid in self.revoked:
                continue
            m = BFTMessage(MessageType.COMMIT, qc.view, qc.sequence, qc.digest, vid, sig, epoch=qc.epoch)
            ok += self._valid(m)
        return ok >= self.quorum_size

    def get_security_state(self) -> dict:
        return {"epoch": self.epoch, "key_rotations": self.rotations, "revoked_validators": sorted(self.revoked),
                "equivocation_proofs": len(self.proofs),
                "active_validators": len(set(self.validators) - self.revoked), "quorum": self.quorum_size}


def demonstrate_hardening() -> HardenedBFTCluster:
    """Small end-to-end check used by run_all: commit, certify, rotate, reject stale key."""
    c = HardenedBFTCluster(n=4)
    seq = c.propose({"auditId": "AUD-DEMO", "action": "Viewed Incident"})
    qc = c.quorum_certificate(seq)
    stolen = c.epoch_keys["V3"]
    c.advance_epoch()
    forged = c.make_message(MessageType.PREPARE, seq + 1, "deadbeef" * 2, "V3", stolen, epoch=0)
    c.send(forged)
    c.run()
    print(f"  committed seq {seq}, QC valid: {qc is not None and c.verify_quorum_certificate(qc)}, "
          f"stale-key messages rejected: {sum(r['reason'] == 'stale_epoch' for r in c.rejections)}")
    return c


if __name__ == "__main__":
    demonstrate_hardening()
