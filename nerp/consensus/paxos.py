"""
Paxos consensus (Resource Allocation Service).

Multi-instance single-decree Paxos: each resource unit (e.g. "Ambulance Unit 3") is
one Paxos instance whose decided value is the incident it is allocated to.
Two different incidents decided for the same unit = double allocation = safety violation.

Implements:
  * Phase 1 (prepare/promise) and Phase 2 (accept/accepted) with ballots (round, proposer)
  * value preservation: proposer adopts the value with the HIGHEST accepted ballot in its quorum
  * acceptor crash / restart, with or without persistent state
  * configurable quorum (refuses non-majority quorums unless explicitly allowed)
"""
from dataclasses import dataclass, field
from typing import Any, Callable, Optional


@dataclass
class SlotState:
    promised: Optional[tuple] = None
    accepted_ballot: Optional[tuple] = None
    accepted_value: Any = None


@dataclass
class Acceptor:
    acceptor_id: str
    region: str = ""
    persistent: bool = True
    up: bool = True
    slots: dict = field(default_factory=dict)

    def _slot(self, slot) -> SlotState:
        return self.slots.setdefault(slot, SlotState())

    def prepare(self, slot, ballot):
        s = self._slot(slot)
        if s.promised is None or ballot > s.promised:
            s.promised = ballot
            return True, s.accepted_ballot, s.accepted_value
        return False, None, None

    def accept(self, slot, ballot, value) -> bool:
        s = self._slot(slot)
        if s.promised is None or ballot >= s.promised:
            s.promised = ballot
            s.accepted_ballot = ballot
            s.accepted_value = value
            return True
        return False

    def crash(self):
        self.up = False
        if not self.persistent:
            self.slots = {}

    def restart(self):
        self.up = True


def _noop_log(node, rnd, event, detail):
    pass


class PaxosCluster:
    def __init__(self, regions: dict[str, list[str]], quorum: Optional[int] = None,
                 persistent: bool = True, allow_unsafe_quorum: bool = False,
                 log: Callable[[str, Any, str, dict], None] = _noop_log):
        self.acceptors: dict[str, Acceptor] = {
            aid: Acceptor(aid, region, persistent) for region, ids in regions.items() for aid in ids}
        self.n = len(self.acceptors)
        self.quorum = quorum or self.n // 2 + 1
        if self.quorum <= self.n // 2 and not allow_unsafe_quorum:
            raise ValueError(f"Quorum {self.quorum} of {self.n} is not a majority: two quorums may not overlap")
        self.round = 0
        self.decided: dict[Any, list] = {}   # slot -> list of (ballot, value) decided
        self.log = log

    def propose(self, slot, value, proposer: str, reach: Optional[list[str]] = None) -> Optional[Any]:
        """Run one Paxos round for slot. reach = acceptors the proposer can contact. Returns decided value."""
        self.round += 1
        ballot = (self.round, proposer)
        targets = [self.acceptors[a] for a in (reach or self.acceptors) if self.acceptors[a].up]

        promises = []
        for a in targets:
            ok, acc_ballot, acc_value = a.prepare(slot, ballot)
            if ok:
                promises.append((a, acc_ballot, acc_value))
        self.log(proposer, self.round, "prepare",
                 {"slot": slot, "ballot": list(ballot), "promises": [a.acceptor_id for a, _, _ in promises]})
        if len(promises) < self.quorum:
            self.log(proposer, self.round, "no_quorum",
                     {"slot": slot, "phase": 1, "got": len(promises), "required": self.quorum})
            return None

        prior = [(b, v) for _, b, v in promises if b is not None]
        if prior:
            b, v = max(prior, key=lambda x: x[0])
            if v != value:
                self.log(proposer, self.round, "adopted_prior_value",
                         {"slot": slot, "wanted": value, "adopted": v, "from_ballot": list(b)})
            value = v

        accepted = [a.acceptor_id for a, _, _ in promises if a.accept(slot, ballot, value)]
        if len(accepted) < self.quorum:
            self.log(proposer, self.round, "no_quorum",
                     {"slot": slot, "phase": 2, "got": len(accepted), "required": self.quorum})
            return None
        self.decided.setdefault(slot, []).append((ballot, value))
        self.log(proposer, self.round, "decided", {"slot": slot, "value": value, "accepted_by": accepted})
        return value

    def crash(self, ids: list[str]):
        for i in ids:
            self.acceptors[i].crash()
        self.log("cluster", self.round, "acceptors_crashed",
                 {"ids": ids, "state_persisted": all(self.acceptors[i].persistent for i in ids)})

    def restart(self, ids: list[str]):
        for i in ids:
            self.acceptors[i].restart()
        self.log("cluster", self.round, "acceptors_restarted",
                 {"ids": ids, "remembered": {i: bool(self.acceptors[i].slots) for i in ids}})

    def check_safety(self) -> dict:
        conflicts = {slot: sorted({repr(v) for _, v in d}) for slot, d in self.decided.items()
                     if len({repr(v) for _, v in d}) > 1}
        return {"conflicting_decisions": conflicts, "safe": not conflicts}

    def get_state(self) -> dict:
        return {"n": self.n, "quorum": self.quorum, "decided": {str(k): [v for _, v in d] for k, d in self.decided.items()},
                "up": [a for a, x in self.acceptors.items() if x.up]}
