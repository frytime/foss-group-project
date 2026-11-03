# Experiment: paxos-state-loss

**Threat:** T7 Datacentre failure (Table 1) · **Protocol:** Paxos (Resource Allocation) · **Boundary:** Operational
**Setup:** 5 acceptors (region-a: A0, A1 · region-b: A2, A3 · region-c: A4), quorum 3. Each resource unit is one Paxos instance; the decided value is the incident it is allocated to. Unit and incidents come from `dispatch.json` / `incidents.json`.
**Run:** `python3 nerp/experiments/paxos-state-loss/run.py`

## Assumption violated
B2: "acceptors must save proposal numbers, promises and accepted values even after restarting". A majority is the system's memory only if that memory survives a crash.

## Change made
1. A region-a dispatcher allocates Ambulance Unit 3 → INC-002 via A0, A1, A2.
2. A1 and A2 lose power and restart.
3. A region-c dispatcher proposes Ambulance Unit 3 → INC-004 via A1, A2, A3. This quorum overlaps the first only at A1 and A2.

Run with persistent acceptor state, then with volatile state (assumption violated). Finally, 3 of 5 acceptors are taken down.

## Behaviour observed
| | Persistent state | Volatile state | Majority lost |
|---|---|---|---|
| First decision | INC-002 | INC-002 | n/a |
| Second proposal | **adopted INC-002** (`adopted_prior_value`) | **decided INC-004** | no quorum: nothing decided |
| Double allocation | no | **yes** | no |

## Properties affected
- **Integrity:** with volatile state the same ambulance is committed to two incidents. That is exactly the safety property Paxos exists to protect.
- **Availability:** with a majority lost there is no progress, but nothing is decided wrongly (safety over liveness).
- **Confidentiality:** not affected.

## Mitigation
Acceptors persist (fsync) promises and accepted values before replying (`persistent=True`). A recovered acceptor with lost state must not rejoin as a voter until it has re-learned state.
**Residual risk:** a disk fault that silently corrupts persisted state looks like a valid acceptor. Paxos tolerates crashes, not corruption (Table 1 T9).
