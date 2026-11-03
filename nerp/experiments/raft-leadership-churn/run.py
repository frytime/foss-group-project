#!/usr/bin/env python3
"""
Experiment raft-leadership-churn  (Threat T8 Network partition / T4-T5 insider or malware on a node;
Raft - Regional Incident DB)

Raft lets any node with a higher term depose the leader. That is safe, but each deposition costs an
election and stalls writes. Two ways to turn it into sustained churn:
  * a flapping link: node C1 (region-c) is cut off for 50 ticks, back for 15, repeatedly. While cut
    off it keeps timing out and incrementing its term; on reconnect that term deposes the leader.
  * a compromised node: B2 runs modified code that inflates its term every 30 ticks (Raft assumes
    crash faults only, so honest nodes believe any term they are shown).
Mitigation tested: Pre-Vote + leader stickiness (Raft thesis s9.6).
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[3]))
from nerp.experiments.explog import ExperimentLog, load_data
from nerp.experiments.raft_workload import DispatchWorkload
from nerp.consensus.raft import RaftCluster

HERE = Path(__file__).parent
REGIONS = {"region-a": ["A1", "A2"], "region-b": ["B1", "B2"], "region-c": ["C1"]}
TICKS = 400
FLAP_NODE, FLAP_DOWN, FLAP_UP = "C1", 50, 15
ATTACKER, INFLATE_EVERY = "B2", 30

SCENARIOS = {
    "A_baseline": {"flap": False, "attacker": False, "pre_vote": False},
    "B_flapping_link": {"flap": True, "attacker": False, "pre_vote": False},
    "C_flapping_link_prevote": {"flap": True, "attacker": False, "pre_vote": True},
    "D_compromised_node_prevote": {"flap": False, "attacker": True, "pre_vote": True},
}


def scenario(L, name: str, cfg: dict, dispatches: list) -> dict:
    L.phase(name, **cfg)
    c = RaftCluster(REGIONS, pre_vote=cfg["pre_vote"], seed=5,
                    log=lambda n, t, e, d: L(n, t, e, {**d, "tick": c.now, "run": name}))
    while c.leader() is None:
        c.tick()
    c.elections = 0
    w = DispatchWorkload(c, dispatches)
    flap_node_term_at_reconnect = []
    attacker_leader_terms = set()
    for i in range(TICKS):
        if cfg["flap"]:
            phase = i % (FLAP_DOWN + FLAP_UP)
            if phase == 0:
                c.isolate(FLAP_NODE)
            elif phase == FLAP_DOWN:
                c.reconnect(FLAP_NODE)
                flap_node_term_at_reconnect.append(
                    {"tick": c.now, "flap_node_term": c.nodes[FLAP_NODE].current_term,
                     "leader_term": max(n.current_term for n in c.nodes.values() if n.node_id != FLAP_NODE)})
        if cfg["attacker"] and i % INFLATE_EVERY == INFLATE_EVERY - 1:
            a = c.nodes[ATTACKER]
            a.current_term = max(n.current_term for n in c.nodes.values()) + 5
            a.voted_for = None
            L(ATTACKER, a.current_term, "term_inflated", {"tick": c.now, "run": name})
        w.step()
        if c.leader() == ATTACKER:
            attacker_leader_terms.add(c.nodes[ATTACKER].current_term)
    w.run(40, send=False)
    res = {**cfg, **w.summary(),
           "flap_node_term_vs_cluster_at_reconnect": flap_node_term_at_reconnect[:4],
           "terms_led_by_compromised_node": len(attacker_leader_terms)}
    L("experiment", 0, "result", {"run": name, **res})
    return res


def main() -> dict:
    L = ExperimentLog(HERE)
    dispatches = load_data("dispatch")
    return {name: scenario(L, name, cfg, dispatches) for name, cfg in SCENARIOS.items()}


if __name__ == "__main__":
    import json
    print(json.dumps(main(), indent=2, default=str))
