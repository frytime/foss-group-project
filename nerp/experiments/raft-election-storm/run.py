#!/usr/bin/env python3
"""
Experiment raft-election-storm  (Threat T1 / T8; Raft - Emergency Dispatch)

Raft's liveness depends on a timing assumption: broadcastTime << electionTimeout << MTBF.
Two realistic operator changes break it:
  * heartbeat interval raised to cut WAN traffic, election timeout left unchanged;
  * election timeouts tuned down "for faster failover", with a narrow randomisation window, on a WAN
    that loses some messages (the communication-reliability assumption also weakens).
Followers then suspect a healthy leader, start elections, and depose it: an election storm.
Mitigations tested: Pre-Vote (does it help?), and validating the timing configuration at start-up.
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[3]))
from nerp.experiments.explog import ExperimentLog, load_data
from nerp.experiments.raft_workload import DispatchWorkload
from nerp.consensus.raft import RaftCluster, TimingConfigError, validate_timing_config

HERE = Path(__file__).parent
REGIONS = {"region-a": ["A1", "A2"], "region-b": ["B1", "B2"], "region-c": ["C1"]}
SEND_TICKS, DRAIN_TICKS = 250, 50

CONFIGS = {
    "A_correct": {"election_timeout": (15, 30), "heartbeat": 3, "pre_vote": False,
                  "why": "baseline: min timeout = 5 x heartbeat, 15-tick randomisation window"},
    "A2_correct_lossy_wan": {"election_timeout": (15, 30), "heartbeat": 3, "pre_vote": False, "loss": 0.10,
                             "why": "baseline config on a degraded WAN (10% message loss)"},
    "B_heartbeat_raised": {"election_timeout": (15, 30), "heartbeat": 20, "pre_vote": False,
                           "why": "heartbeat raised 3 -> 20 to save WAN bandwidth; timeout unchanged"},
    "C_aggressive_timeout_lossy_wan": {"election_timeout": (3, 4), "heartbeat": 3, "pre_vote": False,
                                       "loss": 0.10,
                                       "why": "timeout cut to 3-4 ticks 'for faster failover'; 1-tick "
                                              "window; same 10% message loss"},
    "D_heartbeat_raised_prevote": {"election_timeout": (15, 30), "heartbeat": 20, "pre_vote": True,
                                   "why": "config B with Pre-Vote + leader stickiness enabled"},
}


def scenario(L, name: str, cfg: dict, dispatches: list) -> dict:
    L.phase(name, why=cfg["why"])
    c = RaftCluster(REGIONS, election_timeout=cfg["election_timeout"], heartbeat=cfg["heartbeat"],
                    pre_vote=cfg["pre_vote"], loss=cfg.get("loss", 0.0), seed=11,
                    log=lambda n, t, e, d: L(n, t, e, {**d, "tick": c.now, "run": name}))
    while c.leader() is None:
        c.tick()
    c.elections = 0                       # count only elections after the cluster is up
    w = DispatchWorkload(c, dispatches)
    w.run(SEND_TICKS)
    w.run(DRAIN_TICKS, send=False)
    res = {"config": {k: v for k, v in cfg.items() if k != "why"}, "why": cfg["why"], **w.summary()}
    L("experiment", 0, "result", {"run": name, **res})
    return res


def validation(L) -> dict:
    out = {}
    for name, cfg in CONFIGS.items():
        try:
            validate_timing_config(cfg["election_timeout"], cfg["heartbeat"])
            out[name] = {"accepted": True, "error": None}
        except TimingConfigError as e:
            out[name] = {"accepted": False, "error": str(e)}
    L("experiment", 0, "config_validation", out)
    return out


def main() -> dict:
    L = ExperimentLog(HERE)
    dispatches = load_data("dispatch")
    results = {name: scenario(L, name, cfg, dispatches) for name, cfg in CONFIGS.items()}
    results["E_config_validation"] = validation(L)
    return results


if __name__ == "__main__":
    import json
    print(json.dumps(main(), indent=2, default=str))
