# Experiment: bft-sybil

**Threat:** T6 Supply-chain compromise / rogue nodes (Table 1) · **Protocol:** BFT (National Audit Log) · **Boundary:** Oversight
**Setup:** n = 4, f = 1. The Byzantine primary V0 creates two extra identities (S1, S2) with self-generated Ed25519 keys and uses them to vote for both a real audit entry (`Exported Report`) and a rewritten one (`Viewed Incident`).
**Run:** `python3 nerp/experiments/bft-sybil/run.py`

## Assumption violated
B2: "each validator must have a specific identity". Membership is fixed and controlled, so votes from unknown keys count for nothing.

## Change made
- A: fixed, pre-registered membership.
- B: open membership, where any presented public key is accepted (assumption violated).

## Behaviour observed
| | Closed membership | Open membership |
|---|---|---|
| Sybil messages rejected | 24 (`unknown_validator`) | 0 |
| V1, V2 commit | real entry | real entry |
| V3 commits | nothing | **rewritten entry** |
| Fork | no | **yes** |

## Properties affected
- **Integrity / non-repudiation:** with open membership, one attacker manufactures the extra f votes it needs, and the audit trail forks.
- **Availability / confidentiality:** not affected beyond the fork.

## Mitigation
Fixed membership registry, admitted through governance (implemented). Signatures prove *who* sent a message only if *who* is controlled.
**Residual risk:** the registry is itself a trust anchor. Compromising the admission process is equivalent to an open membership.
