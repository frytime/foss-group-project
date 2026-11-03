# Experiment: raft-election-storm

**Threat:** T1 Denial of service / T8 Network partition (Table 1) · **Protocol:** Raft (Emergency Dispatch) · **Boundary:** Operational
**Setup:** 5 nodes / 3 regions (A1, A2 · B1, B2 · C1). After the first leader is elected, a control-room client sends one dispatch order from `dispatch.json` every 2 ticks for 250 ticks (125 orders), then the cluster runs 50 more ticks to drain. Uncommitted orders are re-sent after 10 ticks (at-least-once delivery). 1 tick ≈ 10 ms.
**Run:** `python3 nerp/experiments/raft-election-storm/run.py`

## Assumption violated
Raft's timing requirement: *broadcastTime ≪ electionTimeout ≪ MTBF*. A follower must normally hear several heartbeats before its timeout fires, and randomised timeouts must be spread widely enough that followers rarely fire together. If either fails, followers suspect a healthy leader and depose it, over and over. This is an election storm.

## Change made
| Run | Election timeout | Heartbeat | Link loss | Pre-Vote | Change |
|---|---|---|---|---|---|
| A | 15–30 | 3 | 0% | off | baseline |
| A2 | 15–30 | 3 | 10% | off | baseline config on a degraded WAN |
| B | 15–30 | **20** | 0% | off | heartbeat raised to save WAN bandwidth; timeout not changed |
| C | **3–4** | 3 | 10% | off | timeout cut "for faster failover"; 1-tick randomisation window |
| D | 15–30 | 20 | 0% | **on** | config B with Pre-Vote + leader stickiness |
| E | – | – | – | – | start-up validation of every config (`validate_timing_config`) |

`RaftCluster(loss=…)` drops each message independently with that probability. `validate_timing_config` requires min timeout ≥ 5 × heartbeat and a randomisation window ≥ 5 ticks.

## Behaviour observed
| | A | A2 | B | C | D |
|---|---|---|---|---|---|
| Elections after start-up | 0 | 0 | 14 | **61** | 13 |
| Leader changes | 0 | 0 | 14 | 31 | 13 |
| Ticks with no leader | 0% | 0% | 24.7% | 19.7% | 28.3% |
| Highest term reached | 1 | 1 | 15 | 55 | 14 |
| Orders committed (of 125) | 125 | 125 | **0** | 125 | **0** |
| Re-sent orders | 0 | 0 | 1,876 | 80 | 1,751 |
| **Duplicate dispatch orders committed** | 0 | 0 | 0 | **3** | 0 |
| Latency median / p95 (ticks) | 2 / 3 | 2 / 3 | – | 3 / 35 | – |
| Safety check | safe | safe | safe | safe | safe |

E: A and A2 are accepted. B, C and D are rejected at start-up (`election timeout min 15 < 5 x heartbeat 20`; `election timeout min 3 < 5 x heartbeat 3; randomisation window 1 < 5 ticks`).

- **B:** every leader was deposed before its first heartbeat reached a follower. New orders reach the leader's log but are never replicated, so nothing committed for 300 ticks. The cluster looked "up" (it kept electing leaders) yet dispatched nothing.
- **C:** with 10% loss, a single missed heartbeat makes a follower fire within 3–4 ticks. Orders still committed, but p95 latency rose 12× and **three orders were committed twice**. The client re-sent each one after its leader vanished, and both copies survived.
- **D:** Pre-Vote did not help. The followers had genuinely not heard from the leader within their timeout, so they granted pre-votes.

## Properties affected
- **Availability:** total loss of dispatch in B and D, degraded in C. Raft safety held in every run.
- **Integrity (application level):** duplicate dispatch orders in C. Raft guarantees a single agreed log, not exactly-once client semantics. A re-sent order is a new log entry.
- **Confidentiality:** none.

## Mitigation
1. **Validate the timing config at start-up** (`RaftCluster(validate_timing=True)`). This rejects B, C and D before they run. It is the only one of the tested mitigations that addresses the root cause.
2. **Idempotent commands:** the state machine should de-duplicate on the order id, so retries during churn cannot dispatch a unit twice.
3. Size timeouts from measured inter-region RTT and loss, and alert on election rate (more than one election per minute means something is wrong).

**Residual risk:** timing is an environmental assumption. A config that passes validation can still storm if the WAN degrades far beyond what was measured. Pre-Vote is not a defence against timing faults (run D).
