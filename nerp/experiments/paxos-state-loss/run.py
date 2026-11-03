#!/usr/bin/env python3
"""
Experiment paxos-state-loss  (Threat T7 Datacentre failure; Paxos - Resource Allocation)

A region allocates an ambulance to an incident. Two acceptors then lose power and restart.
A dispatcher in another region tries to allocate the same ambulance to a different incident.
Run with persistent acceptor state (B2: "acceptors must save promises and accepted values")
and without it (assumption violated). Finally, lose a majority of acceptors.
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[3]))
from nerp.experiments.explog import ExperimentLog, load_data
from nerp.consensus.paxos import PaxosCluster

HERE = Path(__file__).parent
REGIONS = {"region-a": ["A0", "A1"], "region-b": ["A2", "A3"], "region-c": ["A4"]}


def scenario(L, persistent: bool, unit: str, inc1: str, inc2: str) -> dict:
    tag = "persistent_state" if persistent else "volatile_state"
    L.phase(tag)
    p = PaxosCluster(REGIONS, persistent=persistent,
                     log=lambda n, r, e, d: L(n, r, e, {**d, "run": tag}))
    first = p.propose(unit, inc1, "dispatcher-region-a", reach=["A0", "A1", "A2"])
    p.crash(["A1", "A2"])          # power loss in part of region-a / region-b
    p.restart(["A1", "A2"])
    # region-c dispatcher cannot reach A0 (still recovering links); its quorum overlaps the first only at A1, A2
    second = p.propose(unit, inc2, "dispatcher-region-c", reach=["A1", "A2", "A3"])
    safety = p.check_safety()
    result = {"persistent": persistent, "unit": unit, "first_decision": first, "second_decision": second,
              "double_allocation": not safety["safe"], "safety": safety}
    L("experiment", 0, "result", result)
    return result


def majority_loss(L, unit: str, inc: str) -> dict:
    L.phase("majority_loss")
    p = PaxosCluster(REGIONS, log=lambda n, r, e, d: L(n, r, e, {**d, "run": "majority_loss"}))
    p.crash(["A0", "A1", "A2"])
    decided = p.propose(unit, inc, "dispatcher-region-c")
    result = {"acceptors_up": p.get_state()["up"], "decided": decided,
              "available": decided is not None, "safety": p.check_safety()}
    L("experiment", 0, "result", result)
    return result


def main() -> dict:
    L = ExperimentLog(HERE)
    incidents = [i for i in load_data("incidents") if i["assignedAgency"] == "Ambulance"]
    unit = next(d["unit"] for d in load_data("dispatch") if d["unit"].startswith("Ambulance"))
    inc1, inc2 = incidents[0]["incidentId"], incidents[1]["incidentId"]
    return {"persistent_state": scenario(L, True, unit, inc1, inc2),
            "volatile_state": scenario(L, False, unit, inc1, inc2),
            "majority_loss": majority_loss(L, unit, inc2)}


if __name__ == "__main__":
    import json
    print(json.dumps(main(), indent=2, default=str))
