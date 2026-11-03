# Experiment: raft-leadership-churn

**Threat:** T8 Network partition, T5 Malware / T4 Insider on a node (Table 1) · **Protocol:** Raft (Regional Incident DB) · **Boundary:** Operational
**Setup:** 5 nodes / 3 regions, correct timing config (timeout 15–30, heartbeat 3). One dispatch order every 2 ticks for 400 ticks (200 orders), then 40 ticks to drain.
**Run:** `python3 nerp/experiments/raft-leadership-churn/run.py`

## Assumptions violated
1. **Communication reliability:** a node is either reachable or crashed. A *flapping* link is neither. While it is cut off, C1 keeps timing out and incrementing its term. When it reconnects, that higher term forces the healthy leader to step down, even though C1's log is too far behind for it to win.
2. **Crash-fault model:** Raft assumes every node runs the correct code. A node that inflates its term (malware or a malicious operator) is believed by every honest node.

## Change made
| Run | Fault | Mitigation |
|---|---|---|
| A | none | – |
| B | C1's links cut for 50 ticks, restored for 15, repeating | none |
| C | same as B | **Pre-Vote + leader stickiness** (`RaftCluster(pre_vote=True)`) |
| D | B2 runs modified code: every 30 ticks it sets its term to the cluster maximum + 5 | Pre-Vote + leader stickiness |

Pre-Vote (Raft thesis §9.6): before incrementing its term, a candidate asks whether peers *would* vote for it. Peers refuse if they have heard from a leader within the minimum election timeout. Leader stickiness applies the same check to real RequestVote messages.

## Behaviour observed
| | A baseline | B flapping | C flapping + Pre-Vote | D compromised node + Pre-Vote |
|---|---|---|---|---|
| Elections | 0 | 26 | 0 (14 pre-votes failed) | 21 |
| Leader changes | 0 | 6 | **0** | 12 |
| Ticks with no leader | 0% | 31.4% | **0%** | **63.2%** |
| Highest term | 1 | 21 | 1 | 78 |
| Orders committed (of 200) | 200 | 200 | 200 | 200 |
| Latency median / p95 (ticks) | 2 / 3 | 3 / 25 | 2 / 3 | **14 / 54** |
| Terms led by compromised node | – | – | – | 0 |
| Safety check | safe | safe | safe | safe |

In B, C1 reconnected with term 3 against the cluster's term 1, then 6 vs 5, 9 vs 6, 12 vs 11. Each reconnect deposed the leader. In C, C1's term stayed at 1 because its pre-votes failed while it was cut off, so reconnecting was harmless.

## Properties affected
- **Availability:** in B, a third of the run had no leader and dispatch latency rose 8×. In D, the cluster was leaderless most of the time. Every order eventually committed only because the client kept retrying.
- **Integrity / safety:** preserved in every run. The compromised node never became leader, because its log was not more up to date than the others. Raft's vote rule still protected the log.
- **Confidentiality:** none.

## Mitigation
- **Pre-Vote + leader stickiness** fully removes churn from honest-but-flapping nodes (B → C).
- It does **not** stop a compromised node (D). The attacker's inflated term reaches the leader in AppendEntries replies, and Raft obliges the leader to step down. Only ways of stopping a node from lying help: mutually authenticated node identities, attested builds, monitoring for term jumps with automatic eviction, or a BFT protocol where Byzantine nodes must be tolerated (this is why the National Audit Log and Intelligence Distribution use BFT, Task B1).

**Residual risk:** a single compromised Raft node can keep dispatch latency high indefinitely without ever breaking safety, which is a stealthy degradation-of-service attack.
