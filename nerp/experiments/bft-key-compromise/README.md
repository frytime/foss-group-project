# Experiment: bft-key-compromise  (Task B5 evidence)

**Threat:** T6 Supply-chain compromise (Table 1) · **Protocol:** BFT (National Audit Log) · **Boundary:** Oversight
**Setup:** n = 4, f = 1. V0 (the primary) is Byzantine, and the attacker has also stolen the signing key of an **honest** validator, V3 (e.g. through a backdoored dependency). The attacker equivocates on a `Modified Classification` audit entry: real actor vs actor rewritten to "Auditor".
**Run:** `python3 nerp/experiments/bft-key-compromise/run.py`

## Assumption violated
"A valid signature proves who sent a message" (B2). It stops being true once a key is stolen. One Byzantine node plus one stolen key is f+1 faulty signers, even though only one machine misbehaves.

## Change made
- A: baseline BFT, one long-lived key per validator.
- B–D: hardened cluster (`nerp/consensus/hardening.py`):
  - epoch keys certified by a long-term identity key;
  - automatic revocation on a signed equivocation proof;
  - quorum certificates.

## Behaviour observed
| Run | Result |
|---|---|
| A. Baseline | **Fork**: V1 commits the real entry, V2 commits the forged one |
| B. Hardened, key stolen in the current epoch | 2 equivocation proofs → V0 and V3 revoked, their votes purged; **no fork**, nothing committed |
| C. Hardened, key stolen in epoch 0, then rotation | 2 forged messages rejected (`stale_epoch`); V0 revoked after equivocating; **no fork**; V3 not revoked; the epoch-0 quorum certificate (V1, V2, V3) still verifies |
| D. Hardened, **identity** key stolen | Attacker certifies its own epoch key: **accepted** (mechanism defeated) |

## Properties affected
- **Integrity / non-repudiation:** baseline lets a forged attribution enter the audit trail. Hardened runs stop it.
- **Availability:** hardening halts the sequence instead of forking it. Revoking V3 in B removes an honest machine until it is re-keyed.

## Mitigation
Epoch rotation limits how long a stolen key is useful. Equivocation proofs make misuse self-incriminating. Quorum certificates let auditors verify commits offline.
**Residual risk:**
- Identity keys must live in HSMs or offline (run D).
- A thief who signs consistently and never equivocates is only stopped at the next rotation.
- Revocation needs re-keying through governance.
