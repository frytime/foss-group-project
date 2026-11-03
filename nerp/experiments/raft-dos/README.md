# Experiment: raft-dos

**Threat:** T1 Denial of service (Table 1) · **Protocol:** Raft (Emergency Dispatch) · **Boundary:** User → Operational
**Setup:** 5 nodes / 3 regions. A leader processes 50 requests per tick (≈5,000 req/s). From tick 50 to 250 the attacker floods the current leader with 200 malformed requests per tick (≈20,000 req/s) and re-targets the new leader 5 ticks after each change. Legitimate dispatches (from `dispatch.json`) arrive every 2 ticks: 100 during the attack.
**Model assumption:** request handling and heartbeats share one CPU/queue, so a backlog above capacity stops heartbeats.
**Run:** `python3 nerp/experiments/raft-dos/run.py`

## Assumption violated
Raft liveness assumes the leader's heartbeats arrive within the election timeout. The flood breaks that assumption, not Raft's safety rules.

## Change made
- Run 1: no ingress controls.
- Run 2: the paper's mitigation, a rate limit at the external boundary (20 unauthenticated requests per tick admitted). Authenticated responder traffic goes in a priority lane.

## Behaviour observed
| | Unprotected | Rate-limited |
|---|---|---|
| Ticks with an overloaded leader | 206 | 0 |
| Elections / leader changes | 14 / 13 | 1 / 0 |
| Dispatches committed (of 100 sent during attack) | **0** (by end of run) | **100** |
| Commit latency (median / max) | n/a | 2 / 3 ticks |
| Flood requests dropped at gateway | 0 | 36,000 |
| Safety check | safe | safe |

Unprotected, each new leader was overloaded within 5 ticks and then deposed. Legitimate requests sat behind thousands of malformed ones and were re-queued at every leader change.

## Properties affected
- **Availability:** total loss of dispatch while the attack ran unprotected, and the backlog persisted after it stopped.
- **Integrity:** none. Malformed requests were never replicated, and committed logs stayed consistent.
- **Confidentiality:** none.

## Mitigation
Rate limiting at the gateway, plus priority for authenticated traffic (run 2) fully preserved dispatch in this model.
**Residual risk:** this is an application-layer flood. A volumetric DDoS that saturates the links before the gateway still needs upstream scrubbing (Table 1). Leader re-targeting means load balancing alone does not help.
