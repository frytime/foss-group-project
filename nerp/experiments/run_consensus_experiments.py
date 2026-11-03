"""
Consensus experiment runner (Task B4).

Runs every experiments/<protocol>-<attack>/run.py. Each one drives the real Raft / Paxos /
BFT implementations in nerp.consensus, writes its own log.jsonl, and returns its results.
Aggregated results go to experiments/consensus_experiments.json.
"""
import importlib.util
import json
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parents[1]))

EXPERIMENTS = ["raft-partition", "raft-election-storm", "raft-leadership-churn", "raft-dos", "paxos-state-loss", "paxos-quorum-misconfig",
               "bft-equivocation", "bft-sybil", "bft-key-compromise", "bft-audit-corruption"]


def run_experiment(name: str) -> dict:
    spec = importlib.util.spec_from_file_location(f"exp_{name.replace('-', '_')}", HERE / name / "run.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod.main()


def headline(name: str, r: dict) -> str:
    if name == "raft-partition":
        a, b = r["with_check_quorum"], r["without_check_quorum"]
        return (f"check-quorum: old leader steps down after {a['old_leader_stepped_down_after_ticks']} ticks, "
                f"{a['stale_reads_served_by_old_leader']} stale reads | without: "
                f"{b['leaders_during_partition']} leaders, {b['stale_reads_served_by_old_leader']} stale reads | "
                f"safe={a['safety']['safe'] and b['safety']['safe']}")
    if name == "raft-dos":
        a, b = r["unprotected"], r["rate_limited"]
        return (f"unprotected: {a['legit_committed_during_run']}/{a['legit_requests_during_attack']} dispatches "
                f"committed, {a['leader_changes']} leader changes | rate-limited: "
                f"{b['legit_committed_during_run']}/{b['legit_requests_during_attack']}, median "
                f"{b['latency_ticks_median']} ticks")
    if name == "raft-election-storm":
        f = lambda k: (f"{r[k]['elections']} elections, {r[k]['orders_committed']}/{r[k]['orders_sent']} "
                       f"committed, {r[k]['duplicate_commits']} duplicates")
        rejected = [k for k, v in r["E_config_validation"].items() if not v["accepted"]]
        return (f"correct: {f('A_correct')} | heartbeat raised: {f('B_heartbeat_raised')} | aggressive "
                f"timeout+10% loss: {f('C_aggressive_timeout_lossy_wan')} | +pre-vote: "
                f"{r['D_heartbeat_raised_prevote']['orders_committed']} committed | validation rejects {rejected}")
    if name == "raft-leadership-churn":
        f = lambda k: (f"{r[k]['leader_changes']} leader changes, {r[k]['ticks_without_leader_pct']}% leaderless, "
                       f"p95 {r[k]['latency_ticks_p95']} ticks")
        return (f"flapping link: {f('B_flapping_link')} | +pre-vote: {f('C_flapping_link_prevote')} | "
                f"compromised node (+pre-vote): {f('D_compromised_node_prevote')}")
    if name == "paxos-state-loss":
        return (f"persistent: double allocation={r['persistent_state']['double_allocation']} | volatile: "
                f"double allocation={r['volatile_state']['double_allocation']} | majority loss: "
                f"available={r['majority_loss']['available']}")
    if name == "paxos-quorum-misconfig":
        return (f"quorum 2/5: double allocation={r['quorum_2_of_5']['double_allocation']} | quorum 3/5: "
                f"double allocation={r['quorum_3_of_5']['double_allocation']}, minority available="
                f"{r['quorum_3_of_5']['side_2_available']} | bad config rejected="
                f"{r['config_validation']['quorum_2_rejected']}")
    if name == "bft-equivocation":
        return " | ".join(f"{k}: fork={v['fork']}, revoked={v['revoked']}" for k, v in r.items())
    if name == "bft-sybil":
        return " | ".join(f"{k}: fork={v['fork']}, sybil msgs rejected={v['sybil_messages_rejected']}"
                          for k, v in r.items())
    if name == "bft-key-compromise":
        return (f"baseline fork={r['A_baseline']['fork']} | hardened same epoch fork="
                f"{r['B_hardened_same_epoch']['fork']} revoked={r['B_hardened_same_epoch']['revoked']} | "
                f"after rotation stale-key rejections={r['C_hardened_after_rotation']['stale_key_rejections']} | "
                f"identity key stolen: rogue key accepted={r['D_identity_key_stolen']['rogue_epoch_key_accepted']}")
    if name == "bft-audit-corruption":
        t = r["tampering"]
        return (f"tampered entry committed={t['tampered_digest_committed']}, rewritten copy detected="
                f"{r['local_rewrite']['outliers_detected']} | pre-signing corruption committed on "
                f"{r['pre_signing_corruption']['committed_on_honest_validators']} validators")
    return ""


def run_all(output_dir=None) -> dict:
    out = Path(output_dir or HERE)
    print("=" * 60)
    print("NERP CONSENSUS EXPERIMENTS (Task B4)")
    print("=" * 60)
    results = {}
    for name in EXPERIMENTS:
        results[name] = run_experiment(name)
        print(f"[{name}] {headline(name, results[name])}")
    (out / "consensus_experiments.json").write_text(json.dumps(results, indent=2, default=str))
    print(f"[SAVED] {out / 'consensus_experiments.json'}")
    return results


if __name__ == "__main__":
    run_all()
