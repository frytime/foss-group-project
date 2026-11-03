#!/usr/bin/env python3
"""
Experiment bft-sybil  (Threat T6 Supply chain / rogue nodes; BFT - National Audit Log)

One Byzantine primary (f = 1) creates two extra validator identities (S1, S2) with
self-generated keys and uses them to vote for two conflicting audit entries.
  A. fixed, pre-registered membership (assumption: membership is controlled)
  B. open membership - any presented key is accepted (assumption violated)
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[3]))
from cryptography.hazmat.primitives.asymmetric import ed25519

from nerp.experiments.explog import ExperimentLog, load_data
from nerp.consensus.bft import BFTCluster, inject_equivocation

HERE = Path(__file__).parent


def run(L, tag, open_membership, entry) -> dict:
    L.phase(tag, open_membership=open_membership)
    c = BFTCluster(n=4, byzantine=("V0",), open_membership=open_membership,
                   log=lambda n, v, e, d: L(n, v, e, {**d, "run": tag}))
    sybils = {"S1": ed25519.Ed25519PrivateKey.generate(), "S2": ed25519.Ed25519PrivateKey.generate()}
    real = dict(entry)
    erased = {**entry, "action": "Viewed Incident"}          # hide an export
    seq = c.next_seq
    c.next_seq += 1
    inject_equivocation(c, seq, real, erased, to_a=["V1", "V2"], to_b=["V3"],
                        colluders={"V0": c.validators["V0"].private_key, **sybils},
                        primary_key=c.validators["V0"].private_key)
    rejected = [r for r in c.rejections if r["from"] in sybils]
    safety = c.check_safety()
    result = {"open_membership": open_membership, "sybil_identities": list(sybils),
              "sybil_messages_rejected": len(rejected),
              "rejection_reasons": sorted({r["reason"] for r in rejected}),
              "committed": c.committed_at(seq), "fork": not safety["safe"], "safety": safety}
    L("experiment", 0, "result", result)
    return result


def main() -> dict:
    L = ExperimentLog(HERE)
    entry = next(a for a in load_data("audit") if a["action"] == "Exported Report")
    return {"closed_membership": run(L, "closed_membership", False, entry),
            "open_membership": run(L, "open_membership", True, entry)}


if __name__ == "__main__":
    import json
    print(json.dumps(main(), indent=2, default=str))
