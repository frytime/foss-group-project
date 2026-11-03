# Experiment: bft-equivocation

**Threat:** T3 Insider abuse (Table 1) · **Protocol:** BFT (Intelligence Distribution) · **Boundary:** Intelligence
**Setup:** n = 4 validators, f = 1, quorum 2f+1 = 3, Ed25519-signed messages, fixed membership. The Byzantine primary (V0) sends a SEVERE threat report from `intelligence.json` to some honest validators and a copy downgraded to LOW to the others. Its colluders sign PREPARE/COMMIT for both versions.
**Run:** `python3 nerp/experiments/bft-equivocation/run.py`

## Assumption violated
BFT is safe only while at most f = ⌊(n−1)/3⌋ validators are faulty. Run B has f+1 = 2 Byzantine validators.

## Change made
- A: 1 Byzantine (V0).
- B: 2 Byzantine (V0, V3), assumption violated.
- C: as B, with the B5 hardening (equivocation proofs and revocation).

## Behaviour observed
| | A: f = 1 | B: f+1, baseline | C: f+1, hardened |
|---|---|---|---|
| V1 commits | genuine (SEVERE) | genuine | nothing |
| V2 commits | genuine | **downgraded (LOW)** | nothing |
| V3 | honest, no decision (stalled) | Byzantine | Byzantine |
| Fork (honest validators disagree) | no | **yes** | no |
| Revoked | – | – | V0, V3 |

## Properties affected
- **Integrity:** in B, two honest agencies hold contradictory threat assessments for the same report.
- **Availability:** in A, V3 has no decision. In C, nothing is decided. View change is not implemented, so the sequence stays stalled.
- **Accountability:** C produces signed proof of who equivocated.

## Mitigation
Keep faults ≤ f: independent operators, implementation diversity, and a larger n for higher f. Hardening (B5) turns an f+1 fork into a detected, attributable halt.
**Residual risk:** f+1 colluders that never equivocate cannot be told apart from honest validators. A view change is needed to restore liveness.
