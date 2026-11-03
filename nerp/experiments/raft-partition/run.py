#!/usr/bin/env python3
"""
Experiment raft-partition  (Threat T8 Network partition; Raft - Regional Incident DB)

5 Raft nodes over the 3 UK regions. Cut the leader's region off from the others while
responders on both sides keep writing and reading incident state.
Run twice: with check-quorum (leader lease) and with it disabled (assumption violated).
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[3]))
from nerp.experiments.explog import ExperimentLog, load_data
from nerp.consensus.raft import RaftCluster

HERE = Path(__file__).parent
REGIONS = {"region-a": ["A1", "A2"], "region-b": ["B1", "B2"], "region-c": ["C1"]}
PARTITION_TICKS = 120


def scenario(L, check_quorum: bool, incidents: list) -> dict:
    tag = "check_quorum_on" if check_quorum else "check_quorum_off"
    L.phase(tag)
    c = RaftCluster(REGIONS, check_quorum=check_quorum, seed=7,
                    log=lambda n, t, e, d: L(n, t, e, {**d, "tick": c.now, "run": tag}))
    while c.leader() is None:
        c.tick()
    c.run(5)
    for inc in incidents[:3]:
        c.submit(c.leader(), {"incidentId": inc["incidentId"], "status": "open"})
    c.run(10)

    old = c.leader()
    old_region = c.nodes[old].region
    minority = REGIONS[old_region]
    majority = [n for r, ids in REGIONS.items() if r != old_region for n in ids]
    c.partition(minority, majority)
    part_start = c.now

    # Minority-side responder updates INC-004 through the old leader
    minority_write = {"incidentId": incidents[3]["incidentId"], "status": "closed", "by": old_region}
    accepted_by_old = c.submit(old, minority_write) is not None
    old_step_down = new_leader_tick = None
    new_leader = None
    stale_reads = reads_served = 0
    majority_write = None
    for _ in range(PARTITION_TICKS):
        c.tick()
        if old_step_down is None and c.nodes[old].state.value != "leader":
            old_step_down = c.now - part_start
        maj_leaders = [n for n in c.leaders() if n in majority]
        if maj_leaders and new_leader is None:
            new_leader, new_leader_tick = maj_leaders[0], c.now - part_start
            majority_write = {"incidentId": incidents[3]["incidentId"], "status": "escalated",
                              "casualties": 3, "by": c.nodes[new_leader].region}
            c.submit(new_leader, majority_write)
        view = c.read(old)                       # minority responder reads from "its" leader
        if view is not None:
            reads_served += 1
            if majority_write and c.is_committed(majority_write) and majority_write not in view:
                stale_reads += 1
    concurrent_leaders = len(c.leaders())
    L(old, c.nodes[old].current_term, "partition_summary",
      {"run": tag, "old_leader_steps_down_after_ticks": old_step_down,
       "new_leader": new_leader, "new_leader_after_ticks": new_leader_tick,
       "minority_write_accepted_by_old_leader": accepted_by_old,
       "minority_write_committed": c.is_committed(minority_write),
       "stale_reads_served": stale_reads, "reads_served_by_old_leader": reads_served,
       "leaders_at_end_of_partition": c.leaders()})

    c.heal()
    c.run(60)
    safety = c.check_safety()
    result = {
        "check_quorum": check_quorum,
        "old_leader": old, "old_leader_region": old_region,
        "old_leader_stepped_down_after_ticks": old_step_down,
        "new_majority_leader": new_leader, "new_leader_after_ticks": new_leader_tick,
        "leaders_during_partition": concurrent_leaders,
        "minority_write_accepted": accepted_by_old,
        "minority_write_committed_after_heal": c.is_committed(minority_write),
        "majority_write_committed": c.is_committed(majority_write) if majority_write else False,
        "stale_reads_served_by_old_leader": stale_reads,
        "reads_served_by_old_leader": reads_served,
        "elections_total": c.elections,
        "safety": safety,
        "final_leader": c.leader(),
    }
    L("experiment", 0, "result", result)
    return result


def main() -> dict:
    L = ExperimentLog(HERE)
    incidents = load_data("incidents")
    results = {"with_check_quorum": scenario(L, True, incidents),
               "without_check_quorum": scenario(L, False, incidents)}
    return results


if __name__ == "__main__":
    import json
    print(json.dumps(main(), indent=2, default=str))
