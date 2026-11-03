# NERP prototype: how to run it

## Requirements
- Python 3.10 or newer
- `cryptography` (`pip install cryptography`), used for Ed25519 signatures (BFT, signed views) and AES-256-GCM (record encryption and crypto-shredding)

Run every command from this folder, the one that contains `nerp/` and `data/`.

## Run everything
```
python3 nerp/run.py
```
This runs every component in order and writes the evidence to `nerp/experiments/`. A summary is printed and also saved to `nerp/experiments/IMPLEMENTATION_SUMMARY.txt`.

## Run one part
| Part | Command | Evidence written |
|---|---|---|
| A: architecture, threat model | `python3 -m nerp.architecture` | `experiments/architecture.json`, `threat_model.json` |
| B4: all consensus experiments | `python3 nerp/experiments/run_consensus_experiments.py` | `experiments/consensus_experiments.json` |
| B4: a single experiment | `python3 nerp/experiments/<name>/run.py` | `experiments/<name>/log.jsonl` (+ `README.md` write-up) |
| B5: hardening | part of the BFT experiments (`bft-equivocation`, `bft-key-compromise`) | as above |
| C1–C2: classification | `python3 -m nerp.classification_engine` | `classified/*.json`, `experiments/classification_results.json` |
| C3: views | `python3 -m nerp.information_flow part-d` | `experiments/information_views.json` |
| C3–C4: retention, archive, destruction | `python3 -m nerp.retention` | `experiments/retention_evidence.json`, `experiments/retention/governance_log.jsonl` |
| D: policy engine | `python3 -m nerp.policy_engine` | `experiments/policy_conflicts.json` |
| E: governance | `python3 -m nerp.governance` | `experiments/governance.json` |

Run C1–C2 before C3, C4 or D, because those read `nerp/classified/`. `run.py` already does this in the right order.

## Consensus experiments (Task B4)
| Protocol | Required scenario | Experiment |
|---|---|---|
| BFT | equivocation | `bft-equivocation` |
| BFT | Sybil | `bft-sybil` |
| BFT | validator key compromise | `bft-key-compromise` |
| Paxos | state loss | `paxos-state-loss` |
| Paxos | majority loss | `paxos-state-loss` (final run, `majority_loss`) |
| Paxos | quorum misconfiguration | `paxos-quorum-misconfig` |
| Raft | network partitioning | `raft-partition` |
| Raft | election storms | `raft-election-storm` |
| Raft | leadership churn | `raft-leadership-churn` |
| (extra) | Raft leader DoS | `raft-dos` |
| (extra) | BFT audit-log corruption | `bft-audit-corruption` |

All 9 required scenarios are covered. Paxos majority loss has no folder of its own: it is the last run inside `paxos-state-loss` (3 of 5 acceptors taken down; see that experiment's README, column "Majority lost").

## Notes
- The experiments use fixed random seeds, so their numbers are the same on every run. Keys for signing views, pseudonymising research IDs and encrypting records are generated fresh each run by design, so those values change.
- The retention demo runs a simulated clock forward from the snapshot date (2026-11-03) to 26 years. Intelligence and responder records carry no date, so the snapshot date is used for them.
