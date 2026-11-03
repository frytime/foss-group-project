# Experiment: bft-audit-corruption

**Threat:** T9 Data corruption (Table 1) · **Protocol:** BFT (National Audit Log) · **Boundary:** Oversight
**Setup:** n = 4, f = 1, with V3 Byzantine. The Audit Service signs each event from `audit.json` (Ed25519) before submitting it, as the paper describes.
**Run:** `python3 nerp/experiments/bft-audit-corruption/run.py`

## Assumption violated
The paper's residual risk: "corruption that happens before signing or commit is replicated faithfully". The final phase corrupts an event inside the Audit Service, before it is signed.

## Change made
Phase 1: 3 normal events. Phase 2: V3 attempts four tampering attacks while the honest primary proposes the real 4th event:
1. a PRE-PREPARE forged in V0's name;
2. a PRE-PREPARE in V3's own name;
3. a forged PRE-PREPARE whose digest names the real event but whose payload is tampered;
4. PREPARE/COMMIT votes for the tampered event.

Phase 3: V3 serves an auditor a rewritten copy of its log. Phase 4: corruption before signing.

## Behaviour observed
| Attack | Result |
|---|---|
| 1, 3 forged as V0 | rejected at V1 and V2: `bad_signature` (4 rejections) |
| 2 not primary | rejected: `pre_prepare_not_from_primary` (3 rejections) |
| 4 votes for tampered event | never prepared: no honest PRE-PREPARE for that digest |
| Real 4th event | committed on V0, V1, V2; Audit Service signature valid |
| Rewritten local copy | auditor compares hash-chain heads: 3 = 2f+1 agree, **V3 flagged as outlier** |
| Corruption before signing (resource INC-003 → INC-999) | **committed on all 3 honest validators, signature valid** |

## Properties affected
- **Integrity:** protected against a Byzantine replica. Not protected against a faulty source.
- **Non-repudiation:** the committed entries carry valid signatures, including the wrongly corrupted one.
- **Availability / confidentiality:** not affected.

## Mitigation
Signed events, signature-verified BFT messages and 2f+1 hash-chain comparison all held.
**Residual risk (confirmed):** BFT agrees on *what was submitted*, not on *what is true*. Pre-signing corruption needs input validation and reconciliation with the source records.
