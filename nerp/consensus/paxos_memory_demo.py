#!/usr/bin/env python3
"""
Paxos "A majority is the system's memory" (Task B2) - demo on the real PaxosCluster.

1. Quorum overlap: any two majorities of 5 acceptors share at least one acceptor.
2. Memory survival: a later proposer whose majority overlaps the first adopts the decided value.
3. State loss breaks memory: if the overlapping acceptors forget, a conflicting value is decided.
"""
from itertools import combinations

from nerp.consensus.paxos import PaxosCluster

REGIONS = {"region-a": ["A0", "A1"], "region-b": ["A2", "A3"], "region-c": ["A4"]}
IDS = [a for ids in REGIONS.values() for a in ids]


def demonstrate_quorum_overlap() -> bool:
    majorities = list(combinations(IDS, 3))
    return all(set(a) & set(b) for a in majorities for b in majorities)


def demonstrate_memory(persistent: bool):
    p = PaxosCluster(REGIONS, persistent=persistent)
    first = p.propose("Ambulance Unit 3", "INC-002", "P1", reach=["A0", "A1", "A2"])
    p.crash(["A1", "A2"])
    p.restart(["A1", "A2"])
    second = p.propose("Ambulance Unit 3", "INC-004", "P2", reach=["A1", "A2", "A3"])
    return first, second, p.check_safety()["safe"]


if __name__ == "__main__":
    print(f"Every pair of 3-of-5 majorities overlaps: {demonstrate_quorum_overlap()}")
    print(f"Persistent acceptors (first, second, safe): {demonstrate_memory(True)}")
    print(f"Volatile acceptors   (first, second, safe): {demonstrate_memory(False)}")
