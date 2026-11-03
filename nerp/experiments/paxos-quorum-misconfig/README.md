# Experiment: paxos-quorum-misconfig

**Threat:** T8 Network partition (Table 1) · **Protocol:** Paxos (Resource Allocation) · **Boundary:** Operational
**Setup:** 5 acceptors in 3 regions, partitioned into {A0, A1, A2} and {A3, A4}. Each side's dispatcher allocates the same ambulance to a different incident.
**Run:** `python3 nerp/experiments/paxos-quorum-misconfig/run.py`

## Assumption violated
Paxos safety requires every two quorums to share an acceptor (quorum > n/2). An operator lowers the quorum to 2 of 5 "to stay available during partitions".

## Change made
- Run 1: quorum = 2 (assumption violated).
- Run 2: quorum = 3 (majority).
- Run 3: the configuration check in `PaxosCluster` refuses non-majority quorums.

## Behaviour observed
| | Quorum 2 of 5 | Quorum 3 of 5 |
|---|---|---|
| Side 1 decision | INC-002 | INC-002 |
| Side 2 decision | **INC-012** | none (no quorum) |
| Double allocation | **yes** | no |
| Minority side available | yes | no |

Config validation: `PaxosCluster(quorum=2)` → `ValueError: Quorum 2 of 5 is not a majority: two quorums may not overlap`.

## Properties affected
- **Integrity:** a misconfigured quorum gives both partitions authority, so the same ambulance is dispatched twice.
- **Availability:** a correct quorum makes the minority unavailable. That is the trade the paper accepts.
- **Confidentiality:** not affected.

## Mitigation
Majority quorums, enforced at configuration time (implemented). Quorum changes should go through governance review.
**Residual risk:** `allow_unsafe_quorum=True` still exists as an override. Quorum configuration is a privileged, security-critical setting.
