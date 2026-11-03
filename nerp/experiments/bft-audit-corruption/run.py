#!/usr/bin/env python3
"""
Experiment bft-audit-corruption  (Threat T9 Data corruption; BFT - National Audit Log)

The Audit Service signs each audit event, then submits it to the BFT audit log
(n = 4, f = 1). Validator V3 is Byzantine and tries to corrupt the trail:
  1. forge a PRE-PREPARE in the primary's name carrying a tampered event
  2. send a PRE-PREPARE in its own name (it is not the primary)
  3. send a PRE-PREPARE in the primary's name whose digest names the real event but whose
     payload is tampered (caught by the signature check before the digest check)
  4. vote PREPARE/COMMIT for a tampered event while the honest primary proposes the real one
  5. rewrite its own stored copy and serve it to an auditor
Then the assumption the paper flags as residual risk: the event is corrupted BEFORE it is
signed (bug in the Audit Service), and BFT replicates it faithfully.
"""
import hashlib
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[3]))
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric import ed25519

from nerp.experiments.explog import ExperimentLog, load_data
from nerp.consensus.bft import BFTCluster, MessageType, digest_of

HERE = Path(__file__).parent
AUDIT_SERVICE_KEY = ed25519.Ed25519PrivateKey.generate()


def sign_event(event: dict) -> dict:
    body = json.dumps(event, sort_keys=True).encode()
    return {"event": event, "service_sig": AUDIT_SERVICE_KEY.sign(body).hex()}


def event_signature_ok(signed: dict) -> bool:
    try:
        AUDIT_SERVICE_KEY.public_key().verify(bytes.fromhex(signed["service_sig"]),
                                              json.dumps(signed["event"], sort_keys=True).encode())
        return True
    except (InvalidSignature, ValueError):
        return False


def chain_head(entries: list) -> str:
    h = "0" * 64
    for e in entries:
        h = hashlib.sha256((h + json.dumps(e, sort_keys=True)).encode()).hexdigest()
    return h


def main() -> dict:
    L = ExperimentLog(HERE)
    audit = load_data("audit")
    c = BFTCluster(n=4, byzantine=("V3",), log=lambda n, v, e, d: L(n, v, e, d))
    v3 = c.validators["V3"].private_key
    results = {}

    L.phase("normal_operation")
    for ev in audit[:3]:
        c.propose(sign_event(ev))
    results["normal_commits"] = {s: c.committed_at(s) for s in (1, 2, 3)}

    L.phase("byzantine_tampering", attacker="V3")
    real = sign_event(audit[3])
    tampered = {"event": {**audit[3], "action": "Viewed Incident"}, "service_sig": real["service_sig"]}
    seq = c.next_seq
    before = len(c.rejections)
    c.send(c.make_message(MessageType.PRE_PREPARE, seq, tampered, "V0", v3))               # 1 forged as V0
    c.send(c.make_message(MessageType.PRE_PREPARE, seq, tampered, "V3", v3))               # 2 not primary
    bad = c.make_message(MessageType.PRE_PREPARE, seq, digest_of(real), "V0", v3, payload=tampered)
    c.send(bad)                                                                            # 3 digest mismatch
    for t in (MessageType.PREPARE, MessageType.COMMIT):                                    # 4 votes for tampered
        c.send(c.make_message(t, seq, digest_of(tampered), "V3", v3))
    c.run()
    c.propose(real)                                   # honest primary proposes the real event at seq
    committed = c.committed_at(seq)
    honest_payloads = [v.committed[seq][1] for v in c.honest() if seq in v.committed]
    results["tampering"] = {
        "rejections": c.rejections[before:],
        "committed_digests": committed,
        "committed_is_real_event": all(p == real for p in honest_payloads) and len(honest_payloads) == 3,
        "tampered_digest_committed": digest_of(tampered) in committed.values(),
        "service_signature_valid_on_committed": all(event_signature_ok(p) for p in honest_payloads),
        "service_signature_valid_on_tampered": event_signature_ok(tampered),
    }

    L.phase("local_copy_rewrite", attacker="V3")
    honest_logs = {v.validator_id: [v.committed[s][1] for s in sorted(v.committed)] for v in c.honest()}
    v3_claimed = [dict(e) for e in next(iter(honest_logs.values()))]
    v3_claimed[3] = tampered                          # V3 serves a rewritten history
    heads = {vid: chain_head(log) for vid, log in honest_logs.items()}
    heads["V3"] = chain_head(v3_claimed)
    counts = {h: list(heads.values()).count(h) for h in set(heads.values())}
    agreed = max(counts, key=counts.get)
    outliers = [vid for vid, h in heads.items() if h != agreed]
    L("auditor", 0, "chain_head_comparison", {"heads": heads, "agreed_by": counts[agreed], "outliers": outliers})
    results["local_rewrite"] = {"agreed_head_votes": counts[agreed], "quorum": c.quorum_size,
                                "outliers_detected": outliers}

    L.phase("corruption_before_signing")
    corrupted = dict(audit[4])
    corrupted["resource"] = "INC-999"                 # bug in the Audit Service before signing
    seq2 = c.propose(sign_event(corrupted))
    p2 = [v.committed[seq2][1] for v in c.honest() if seq2 in v.committed]
    results["pre_signing_corruption"] = {
        "committed_on_honest_validators": len(p2),
        "signature_valid": all(event_signature_ok(p) for p in p2),
        "committed_resource": p2[0]["event"]["resource"] if p2 else None,
        "original_resource": audit[4]["resource"],
    }
    results["safety"] = c.check_safety()
    L("experiment", 0, "result", {k: v for k, v in results.items() if k != "tampering"} |
      {"tampering": {k: v for k, v in results["tampering"].items() if k != "rejections"}})
    return results


if __name__ == "__main__":
    print(json.dumps(main(), indent=2, default=str))
