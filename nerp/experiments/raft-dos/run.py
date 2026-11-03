#!/usr/bin/env python3
"""
Experiment raft-dos  (Threat T1 Denial of service; Raft - Emergency Dispatch)

The attacker floods whichever node is the current Raft leader with malformed requests.
Model assumption: the leader's request handling and its heartbeats share one CPU/queue,
so when the request backlog exceeds what it can process in a tick, heartbeats are not sent.
Run twice: no ingress controls (assumption violated), then rate limiting at the external
boundary with priority for authenticated responder traffic (paper's mitigation).
1 tick ~ 10 ms.
"""
import statistics
import sys
from collections import deque
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[3]))
from nerp.experiments.explog import ExperimentLog, load_data
from nerp.consensus.raft import RaftCluster

HERE = Path(__file__).parent
REGIONS = {"region-a": ["A1", "A2"], "region-b": ["B1", "B2"], "region-c": ["C1"]}
CAPACITY = 50          # requests a leader can process per tick (~5,000 req/s)
FLOOD = 200            # attacker requests per tick (~20,000 req/s)
RATE_LIMIT = 20        # unauthenticated requests admitted per tick at the gateway
RETARGET_DELAY = 5     # ticks for the attacker to find the new leader
ATTACK = (50, 250)
TOTAL = 320


def scenario(L, mitigated: bool, dispatches: list) -> dict:
    tag = "rate_limited" if mitigated else "unprotected"
    L.phase(tag, capacity=CAPACITY, flood=FLOOD, rate_limit=RATE_LIMIT if mitigated else None)
    c = RaftCluster(REGIONS, seed=3, log=lambda n, t, e, d: L(n, t, e, {**d, "tick": c.now, "run": tag}))
    while c.leader() is None:
        c.tick()
    queues: dict[str, deque] = {n: deque() for n in c.nodes}
    target, target_since = c.leader(), c.now
    legit = []                       # dicts: submit_tick, command, committed_tick
    pending_retry = deque()
    flood_rejected = 0
    overloaded_ticks = 0
    leaders_seen = [c.leader()]
    seq = 0

    for _ in range(TOTAL):
        leader = c.leader()
        if leader and leader != leaders_seen[-1]:
            leaders_seen.append(leader)
        attacking = ATTACK[0] <= c.now < ATTACK[1]
        # attacker re-targets the leader after a delay
        if leader and leader != target and c.now - target_since >= RETARGET_DELAY:
            target, target_since = leader, c.now
        # arrivals
        if attacking and target:
            n_flood = min(FLOOD, RATE_LIMIT) if mitigated else FLOOD
            queues[target].extend([("flood", None)] * n_flood)
            flood_rejected += (FLOOD - n_flood)  # dropped at the gateway
        if c.now % 2 == 0:
            d = dispatches[seq % len(dispatches)]
            req = {"submit_tick": c.now, "committed_tick": None,
                   "command": {"dispatchId": d["dispatchId"], "unit": d["unit"], "seq": seq}}
            seq += 1
            legit.append(req)
            pending_retry.append(req)
        # gateway routes legit traffic to the current leader (priority lane if mitigated)
        while pending_retry and leader:
            req = pending_retry.popleft()
            if mitigated:
                queues[leader].appendleft(("legit", req))
            else:
                queues[leader].append(("legit", req))
        # each node processes CAPACITY items
        c.overloaded = set()
        for nid, q in queues.items():
            for _ in range(min(CAPACITY, len(q))):
                kind, req = q.popleft()
                if kind == "flood":
                    continue                       # rejected by validation
                if c.submit(nid, req["command"]) is None:
                    pending_retry.append(req)      # not leader any more: client retries
            if len(q) > CAPACITY and c.nodes[nid].state.value == "leader":
                c.overloaded.add(nid)
        if c.overloaded:
            overloaded_ticks += 1
        c.tick()
        for req in legit:
            if req["committed_tick"] is None and c.is_committed(req["command"]):
                req["committed_tick"] = c.now

    in_attack = [r for r in legit if ATTACK[0] <= r["submit_tick"] < ATTACK[1]]
    lat = [r["committed_tick"] - r["submit_tick"] for r in in_attack if r["committed_tick"] is not None]
    result = {
        "mitigated": mitigated,
        "legit_requests_during_attack": len(in_attack),
        "legit_committed_during_run": sum(r["committed_tick"] is not None for r in in_attack),
        "latency_ticks_median": statistics.median(lat) if lat else None,
        "latency_ticks_max": max(lat) if lat else None,
        "elections_total": c.elections,
        "leader_changes": len(leaders_seen) - 1,
        "ticks_leader_overloaded": overloaded_ticks,
        "flood_dropped_at_gateway": flood_rejected,
        "safety": c.check_safety(),
    }
    L("experiment", 0, "result", result)
    return result


def main() -> dict:
    L = ExperimentLog(HERE)
    dispatches = load_data("dispatch")
    return {"unprotected": scenario(L, False, dispatches), "rate_limited": scenario(L, True, dispatches)}


if __name__ == "__main__":
    import json
    print(json.dumps(main(), indent=2, default=str))
