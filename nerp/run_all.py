#!/usr/bin/env python3
"""
NERP Prototype - Main Runner.
Runs every component and writes evidence for the Security Assurance Portfolio to nerp/experiments/.
All printed findings are computed from the results of this run.
"""
import json
import sys
from datetime import datetime
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from nerp.architecture import build_nerp_architecture, save_architecture, THREATS, ASSURANCE_SUMMARY
from nerp.consensus.analysis import consensus_selection_analysis, save_analysis
from nerp.consensus.hardening import demonstrate_hardening
from nerp.classification_engine import run as run_classification
from nerp.information_flow import run_part_d as run_information_flow
from nerp.policy_engine import save_policy_evidence
from nerp.retention import run as run_retention
from nerp.governance import IMPACT_ASSESSMENTS, GOVERNANCE_DECISIONS, save_governance
from nerp.experiments.run_consensus_experiments import run_all as run_consensus_experiments, headline


def run_full_prototype() -> dict:
    evidence_dir = PROJECT_ROOT / "nerp" / "experiments"
    evidence_dir.mkdir(parents=True, exist_ok=True)
    ev = {"timestamp": datetime.now().isoformat(), "components": {}}
    comp = ev["components"]
    print("=" * 70)
    print("NERP PROTOTYPE EXECUTION")
    print("=" * 70)

    print("\n[1/9] Architecture and threat model (Part A)")
    arch = build_nerp_architecture()
    save_architecture(evidence_dir)
    comp["architecture"] = {"services": len(arch.services),
                            "trust_boundaries": [t.value for t in arch.trust_boundaries],
                            "security_domains": [d.value for d in arch.security_domains],
                            "assurance_summary": ASSURANCE_SUMMARY}
    comp["threat_model"] = [{"id": t["id"], "name": t["name"], "stride": t["stride"], "tool_id": t["tool_id"],
                             "experiment": t["experiment"]} for t in THREATS]

    print("\n[2/9] Consensus selection (Task B1)")
    selections = consensus_selection_analysis()
    save_analysis(evidence_dir / "consensus_analysis.json")
    comp["consensus_selection"] = {s.subsystem.value: s.selected.value for s in selections}

    print("\n[3/9] Consensus experiments (Task B4)")
    comp["consensus_experiments"] = run_consensus_experiments(evidence_dir)

    print("\n[4/9] Hardening mechanism (Task B5)")
    comp["hardening"] = demonstrate_hardening().get_security_state()

    print("\n[5/9] Classification (Part C1-C2)")
    comp["classification"] = run_classification()

    print("\n[6/9] Information flow views (Part C3)")
    comp["information_flow"] = run_information_flow()

    print("\n[7/9] Retention, archiving and secure destruction (Part C3/C4)")
    ret = run_retention()
    comp["retention"] = {"final": ret["enforcement"]["timeline"][-1], "probes": ret["enforcement"]["probes"],
                         "log_integrity": ret["enforcement"]["log_integrity"],
                         "regulation_20y": ret["regulation_20y"]}

    print("\n[8/9] Policy engine (Part D)")
    comp["policy_engine"] = save_policy_evidence(evidence_dir)
    for sc in comp["policy_engine"]["scenarios"]:
        print(f"  {sc['scenario']}: ACM={sc['acm']} BLP={sc['bell_lapadula']} Biba={sc['biba']} "
              f"-> {sc['final'].upper()}")

    print("\n[9/9] Governance (Part E)")
    save_governance(evidence_dir / "governance.json", retention_20y=ret["regulation_20y"])
    comp["governance"] = {"impact_assessments": len(IMPACT_ASSESSMENTS),
                          "governance_decisions": len(GOVERNANCE_DECISIONS)}

    (evidence_dir / "master_evidence.json").write_text(json.dumps(ev, indent=2, default=str))
    summary = generate_implementation_summary(ev)
    (evidence_dir / "IMPLEMENTATION_SUMMARY.txt").write_text(summary)
    print("\n" + summary)
    print(f"\n[SAVED] {evidence_dir / 'master_evidence.json'}")
    print(f"[SAVED] {evidence_dir / 'IMPLEMENTATION_SUMMARY.txt'}")
    return ev


def generate_implementation_summary(ev: dict) -> str:
    c = ev["components"]
    a = c["architecture"]
    lines = ["NERP PROTOTYPE - IMPLEMENTATION SUMMARY", "=" * 60, f"Generated: {ev['timestamp']}", "",
             "PART A - ARCHITECTURE & THREAT MODEL",
             f"  {a['services']} services, {len(a['security_domains'])} security domains "
             f"({', '.join(a['security_domains'])}), {len(a['trust_boundaries'])} trust boundaries "
             f"({', '.join(a['trust_boundaries'])})",
             f"  {len(c['threat_model'])} threats (Table 1):"]
    lines += [f"    {t['id']} {t['name']} [STRIDE {t['stride']}, tool {t['tool_id']}]"
              + (f" -> {', '.join(t['experiment'])}" if t["experiment"] else "") for t in c["threat_model"]]
    lines += ["", "PART B - CONSENSUS",
              "  Selection: " + ", ".join(f"{k}={v}" for k, v in c["consensus_selection"].items()),
              "  Experiments (each drives the real protocol code; logs in experiments/<name>/log.jsonl):"]
    lines += [f"    {name}: {headline(name, r)}" for name, r in c["consensus_experiments"].items()]
    h = c["hardening"]
    lines += ["  Hardening (B5): epoch-scoped Ed25519 keys + equivocation-proof revocation + quorum certificates",
              f"    demo: epoch {h['epoch']}, rotations {h['key_rotations']}, active validators "
              f"{h['active_validators']}, quorum {h['quorum']}",
              "", "PART C - CLASSIFICATION & INFORMATION FLOW"]
    lines += [f"  {'dataset':12s} OFFICIAL CONFIDENTIAL SECRET TOP_SECRET  raised above baseline"]
    for name, cs in c["classification"].items():
        bl = cs["by_label"]
        lines.append(f"  {name:12s} {bl['OFFICIAL']:8d} {bl['CONFIDENTIAL']:12d} {bl['SECRET']:6d} "
                     f"{bl['TOP_SECRET']:10d}  {', '.join(cs['raised_above_baseline']) or '-'}")
    lines += ["  review queue: " + "; ".join(f"{n}: {', '.join(cs['review_queue'])}"
                                             for n, cs in c["classification"].items() if cs["review_queue"])]
    f = c["information_flow"]
    ch = f["checks"]
    lines += ["  Views (classified -> operational -> analytics -> research):"]
    lines += [f"    {v}: {n}" for v, n in f["record_counts"].items()]
    lines += [f"    flow checks: " + ", ".join(f"{v}={'pass' if x['pass'] else 'FAIL'}"
                                            for v, x in ch["flow_properties"].items())
              + f"; signatures valid={all(ch['signatures_valid'].values())}; tampering detected="
              f"{ch['tampered_research_view_detected']}",
              f"    research: k={f['research_generalisation']['k']} at {f['research_generalisation']['generalisation_level']}"
              f", suppressed {len(f['research_generalisation']['suppressed'])}; re-identification "
              f"{ch['reidentification']['v1_unsalted_sha256_reidentified']} (old hash) vs "
              f"{ch['reidentification']['v2_hmac_pids_matched_by_enumeration']} (HMAC)"]
    r = c["retention"]
    pr = r["probes"]
    lines += ["  Retention (C4): tiers after 26 years " + json.dumps(r["final"]["tiers"]),
              f"    legal holds {r['final']['legal_holds']}; caller PII after 31 days: {pr['pii_after_31_days']}",
              f"    destroyed record readable={pr['read_destroyed_record']['allowed']}; destroy under hold allowed="
              f"{pr['destroy_under_legal_hold']['allowed']}; early audit deletion allowed="
              f"{pr['early_destroy_audit_by_auditor']['allowed']}",
              f"    governance log chain valid={r['log_integrity']['chain_valid']}, forgery detected="
              f"{r['log_integrity']['forged_copy_detected']}",
              f"    20-year regulation: record-years {r['regulation_20y']['record_years_before']} -> "
              f"{r['regulation_20y']['record_years_after']}",
              "", "PART D - POLICY ENGINE (ACM + Bell-LaPadula + Biba, deny if any denies)"]
    for s in c["policy_engine"]["scenarios"]:
        lines.append(f"  {s['scenario']}: ACM={s['acm']} BLP={s['bell_lapadula']} Biba={s['biba']} "
                     f"-> {s['final'].upper()}")
    lines += ["", "GOVERNANCE",
              f"  {c['governance']['impact_assessments']} impact assessments, "
              f"{c['governance']['governance_decisions']} decisions",
              "", "VERIFY", "  python3 nerp/run.py",
              "  python3 nerp/experiments/run_consensus_experiments.py",
              "  python3 nerp/experiments/<experiment>/run.py",
              "  python3 -m nerp.information_flow part-d  # C3 views + checks",
              "  python3 -m nerp.retention                # C4 retention / archive / destruction",
              "  python3 -m nerp.policy_engine            # Part D scenarios + outcome matrix"]
    return "\n".join(lines)


if __name__ == "__main__":
    run_full_prototype()
