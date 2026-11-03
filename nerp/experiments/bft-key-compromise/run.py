#!/usr/bin/env python3
"""
Experiment bft-key-compromise  (Threat T6 Supply chain; BFT - National Audit Log; Task B5 evidence)

One validator (V0, the primary) is Byzantine and the attacker has also stolen the signing
key of an HONEST validator (V3), e.g. via a backdoored dependency. That is f + 1 faulty
signers while every node except V0 still behaves correctly.
  A. baseline BFT (one long-lived key per validator)
  B. hardened, key stolen in the current epoch      -> equivocation proofs revoke both identities
  C. hardened, key stolen in an earlier epoch       -> stolen key expired at rotation
  D. hardened, identity key stolen (residual risk)  -> attacker can certify its own epoch key
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[3]))
from cryptography.hazmat.primitives.asymmetric import ed25519

from nerp.experiments.explog import ExperimentLog, load_data
from nerp.consensus.bft import BFTCluster, MessageType, inject_equivocation
from nerp.consensus.hardening import HardenedBFTCluster

HERE = Path(__file__).parent


def attack(c, entry, colluders, primary_key) -> dict:
    real = dict(entry)
    forged = {**entry, "actor": "Auditor"}               # misattribute the action
    seq = c.next_seq
    c.next_seq += 1
    # V3 is honest but its key is stolen; the primary splits V1 and V2
    inject_equivocation(c, seq, real, forged, to_a=["V1"], to_b=["V2"],
                        colluders=colluders, primary_key=primary_key)
    safety = c.check_safety()
    return {"committed": c.committed_at(seq), "fork": not safety["safe"], "safety": safety,
            "rejection_reasons": sorted({r["reason"] for r in c.rejections})}


def main() -> dict:
    L = ExperimentLog(HERE)
    audit = load_data("audit")
    entry = next(a for a in audit if a["action"] == "Modified Classification")
    log = lambda tag: (lambda n, v, e, d: L(n, v, e, {**d, "run": tag}))
    results = {}

    L.phase("A_baseline")
    c = BFTCluster(n=4, byzantine=("V0",), log=log("A_baseline"))
    results["A_baseline"] = attack(c, entry, {"V0": c.validators["V0"].private_key,
                                              "V3": c.validators["V3"].private_key},
                                   c.validators["V0"].private_key)

    L.phase("B_hardened_same_epoch")
    h = HardenedBFTCluster(n=4, byzantine=("V0",), log=log("B_hardened_same_epoch"))
    r = attack(h, entry, {"V0": h.epoch_keys["V0"], "V3": h.epoch_keys["V3"]}, h.epoch_keys["V0"])
    results["B_hardened_same_epoch"] = {**r, "revoked": sorted(h.revoked), "proofs": len(h.proofs)}

    L.phase("C_hardened_after_rotation")
    h = HardenedBFTCluster(n=4, byzantine=("V0",), log=log("C_hardened_after_rotation"))
    stolen = h.epoch_keys["V3"]
    first = h.propose(audit[0])                       # normal traffic in epoch 0
    qc = h.quorum_certificate(first)
    h.advance_epoch()                                 # scheduled rotation
    # attacker replays the stolen epoch-0 key as V3
    stale = h.make_message(MessageType.PREPARE, h.next_seq, "00" * 8, "V3", stolen, epoch=0)
    h.send(stale)
    h.run()
    r = attack(h, entry, {"V0": h.epoch_keys["V0"]}, h.epoch_keys["V0"])
    results["C_hardened_after_rotation"] = {
        **r, "revoked": sorted(h.revoked), "proofs": len(h.proofs),
        "stale_key_rejections": sum(x["reason"] == "stale_epoch" for x in h.rejections),
        "epoch_0_quorum_certificate_valid": qc is not None and h.verify_quorum_certificate(qc),
        "qc_signers": sorted(qc.signatures) if qc else []}

    L.phase("D_identity_key_stolen")
    h = HardenedBFTCluster(n=4, byzantine=("V0",), log=log("D_identity_key_stolen"))
    identity_v3 = h.validators["V3"].private_key       # long-term key, normally offline/HSM
    rogue = ed25519.Ed25519PrivateKey.generate()
    cert = identity_v3.sign(h._cert_bytes("V3", h.epoch, rogue.public_key()))
    accepted = h.register_epoch_key("V3", h.epoch, rogue.public_key(), cert)
    L("V3", 0, "rogue_epoch_key_registered", {"accepted": accepted})
    results["D_identity_key_stolen"] = {"rogue_epoch_key_accepted": accepted}
    L("experiment", 0, "result", results)
    return results


if __name__ == "__main__":
    import json
    print(json.dumps(main(), indent=2, default=str))
