# Experiment: raft-partition

**Threat:** T8 Network partition (Table 1) · **Protocol:** Raft (Regional Incident DB) · **Boundary:** Operational
**Setup:** 5 nodes across 3 regions (region-a: A1, A2 · region-b: B1, B2 · region-c: C1), quorum 3, election timeout 15–30 ticks, heartbeat 3 ticks (1 tick ≈ 10 ms). The leader's region is cut off for 120 ticks while responders on both sides write and read INC-004. Run twice.
**Run:** `python3 nerp/experiments/raft-partition/run.py`

## Assumption violated
Raft's safety covers the *committed log*. Serving reads from a node that merely *believes* it is leader assumes that node still holds a majority (leader lease / check-quorum). The second run removes check-quorum.

## Change made
- Run 1: check-quorum on. A leader that has not heard from a majority within the minimum election timeout steps down.
- Run 2: check-quorum off (assumption violated).

## Behaviour observed
| | check-quorum on | check-quorum off |
|---|---|---|
| Partitioned leader | B2 (region-b) | B2 (region-b) |
| Old leader steps down | after 16 ticks | never during the partition |
| New majority leader | C1 after 16 ticks | C1 after 16 ticks |
| Nodes acting as leader during partition | 1 | **2** |
| Minority write (INC-004 "closed") | accepted, never committed, truncated on heal | same |
| Majority write (INC-004 "escalated", 3 casualties) | committed | committed |
| Stale reads served by old leader | 0 | **102 of 120** |
| Safety check (one leader per term, committed logs agree) | safe | safe |

After healing in run 1, the minority nodes had run repeated failed elections, so they came back with a higher term (8). That forced C1 to step down and A2 to be elected: 9 elections in total versus 2 in run 2.

## Properties affected
- **Integrity / consistency:** committed state never diverged in either run.
- **Confidentiality:** not affected.
- **Availability:** the minority region loses write access, as the paper says. Its write was silently dropped on heal.
- **Operational correctness:** without check-quorum, region-b responders read an incident state that was 102 ticks out of date. That is the paper's "regions act on different incident states".

## Mitigation
Check-quorum / leader lease (implemented, run 1), so the minority side has no leader instead of a stale one. Clients must treat uncommitted writes as failed and retry.
**Residual risk:** disruptive rejoin after heal (an extra election). Raft's PreVote extension would prevent this but is not implemented. The minority region has no write availability until the partition heals.
