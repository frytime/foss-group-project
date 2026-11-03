#!/usr/bin/env python3
"""
Experiment bft-equivocation  (Threat T3 Insider abuse; BFT - Intelligence Distribution)

A compromised primary distributes a threat report to some validators and a downgraded
copy (threat level lowered to LOW) to others, while its colluders vote for both.
  A. f = 1 Byzantine validator out of n = 4  (assumption holds)
  B. f + 1 = 2 Byzantine validators          (assumption "at most f faulty" violated)
  C. as B, with the B5 hardening (equivocation proofs + revocation)
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[3]))
from nerp.experiments.explog import ExperimentLog, load_data
from nerp.consensus.bft import BFTCluster, inject_equivocation
from nerp.consensus.hardening import HardenedBFTCluster

HERE = Path(__file__).parent


def run(L, tag, cluster_cls, byzantine, report) -> dict:
    L.phase(tag, byzantine=list(byzantine))
    c = cluster_cls(n=4, byzantine=byzantine, log=lambda n, v, e, d: L(n, v, e, {**d, "run": tag}))
    key = (lambda vid: c.epoch_keys[vid]) if isinstance(c, HardenedBFTCluster) else \
          (lambda vid: c.validators[vid].private_key)
    genuine = {k: report[k] for k in ("reportId", "reportSource", "threatLevel", "region", "summary")}
    downgraded = {**genuine, "threatLevel": "LOW"}
    seq = c.next_seq
    c.next_seq += 1
    honest = [v.validator_id for v in c.honest()]
    d_a, d_b = inject_equivocation(c, seq, genuine, downgraded, to_a=honest[:(len(honest) + 1) // 2],
                                   to_b=honest[(len(honest) + 1) // 2:],
                                   colluders={b: key(b) for b in byzantine}, primary_key=key(c.primary()))
    committed = c.committed_at(seq)
    safety = c.check_safety()
    result = {
        "byzantine": list(byzantine), "f_tolerated": c.f, "honest": honest,
        "digest_genuine": d_a, "digest_downgraded": d_b,
        "committed": committed,
        "honest_validators_without_decision": [h for h in honest if h not in committed],
        "fork": not safety["safe"], "safety": safety,
        "revoked": sorted(getattr(c, "revoked", [])),
    }
    L("experiment", 0, "result", result)
    return result


def main() -> dict:
    L = ExperimentLog(HERE)
    report = next(r for r in load_data("intelligence") if r["threatLevel"] in ("SEVERE", "CRITICAL"))
    return {
        "f1_baseline": run(L, "f1_baseline", BFTCluster, ("V0",), report),
        "f2_baseline": run(L, "f2_baseline", BFTCluster, ("V0", "V3"), report),
        "f2_hardened": run(L, "f2_hardened", HardenedBFTCluster, ("V0", "V3"), report),
    }


if __name__ == "__main__":
    import json
    print(json.dumps(main(), indent=2, default=str))
