#!/usr/bin/env python3
"""
Experiment paxos-quorum-misconfig  (Threat T8 Network partition; Paxos - Resource Allocation)

Paxos safety rests on quorum overlap: any two quorums must share an acceptor.
An operator lowers the quorum to 2 of 5 "to stay available during partitions"
(assumption violated). The regions are then partitioned and each side allocates the
same unit. Then the same partition with the correct majority quorum, and finally the
configuration check that refuses non-majority quorums.
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[3]))
from nerp.experiments.explog import ExperimentLog, load_data
from nerp.consensus.paxos import PaxosCluster

HERE = Path(__file__).parent
REGIONS = {"region-a": ["A0", "A1"], "region-b": ["A2", "A3"], "region-c": ["A4"]}
SIDE_1, SIDE_2 = ["A0", "A1", "A2"], ["A3", "A4"]


def run_partition(L, tag, quorum, unit, inc1, inc2) -> dict:
    L.phase(tag, quorum=quorum, sides=[SIDE_1, SIDE_2])
    p = PaxosCluster(REGIONS, quorum=quorum, allow_unsafe_quorum=True,
                     log=lambda n, r, e, d: L(n, r, e, {**d, "run": tag}))
    a = p.propose(unit, inc1, "dispatcher-side-1", reach=SIDE_1)
    b = p.propose(unit, inc2, "dispatcher-side-2", reach=SIDE_2)
    safety = p.check_safety()
    result = {"quorum": quorum, "side_1_decision": a, "side_2_decision": b,
              "double_allocation": not safety["safe"], "side_2_available": b is not None, "safety": safety}
    L("experiment", 0, "result", result)
    return result


def main() -> dict:
    L = ExperimentLog(HERE)
    incidents = [i for i in load_data("incidents") if i["assignedAgency"] == "Ambulance"]
    unit = next(d["unit"] for d in load_data("dispatch") if d["unit"].startswith("Ambulance"))
    inc1, inc2 = incidents[0]["incidentId"], incidents[2]["incidentId"]
    results = {"quorum_2_of_5": run_partition(L, "misconfigured_quorum", 2, unit, inc1, inc2),
               "quorum_3_of_5": run_partition(L, "majority_quorum", 3, unit, inc1, inc2)}
    L.phase("config_validation")
    try:
        PaxosCluster(REGIONS, quorum=2)
        rejected, reason = False, None
    except ValueError as e:
        rejected, reason = True, str(e)
    L("config", 0, "config_rejected" if rejected else "config_accepted", {"quorum": 2, "reason": reason})
    results["config_validation"] = {"quorum_2_rejected": rejected, "reason": reason}
    return results


if __name__ == "__main__":
    import json
    print(json.dumps(main(), indent=2, default=str))
