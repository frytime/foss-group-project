"""
Shared dispatch workload for the Raft liveness experiments (raft-election-storm, raft-leadership-churn).

A control-room client sends one dispatch order (from dispatch.json) every `every` ticks to whichever
node is currently leader. If the order is not committed within `retry_after` ticks it is re-sent
(at-least-once delivery, as a real client would do when the leader it used has disappeared).
The driver records per-tick leadership so experiments can measure election storms and churn.
"""
import statistics


class DispatchWorkload:
    def __init__(self, cluster, dispatches: list, every: int = 2, retry_after: int = 10):
        self.c = cluster
        self.dispatches = dispatches
        self.every = every
        self.retry_after = retry_after
        self.pending: dict[str, dict] = {}     # req id -> {cmd, first, last_sent}
        self.done: dict[str, int] = {}         # req id -> latency in ticks
        self.sent = 0
        self.resends = 0
        self.rejected_no_leader = 0
        self.leader_trace: list = []           # leader id (or None) per tick
        self.max_term = 0

    def _committed_ids(self) -> set:
        ids = set()
        for n in self.c.nodes.values():
            for e in n.log[:n.commit_index]:
                if isinstance(e.command, dict) and "req" in e.command:
                    ids.add(e.command["req"])
        return ids

    def step(self, send: bool = True):
        c = self.c
        if send and c.now % self.every == 0:
            d = self.dispatches[self.sent % len(self.dispatches)]
            req = f"{d['dispatchId']}#{self.sent}"
            cmd = {"req": req, "dispatchId": d["dispatchId"], "incidentId": d["incidentId"], "unit": d["unit"]}
            self.pending[req] = {"cmd": cmd, "first": c.now, "last_sent": None}
            self.sent += 1
        leader = c.leader()
        for req, p in self.pending.items():
            if p["last_sent"] is None or c.now - p["last_sent"] >= self.retry_after:
                if leader is None:
                    self.rejected_no_leader += 1
                    continue
                if p["last_sent"] is not None:
                    self.resends += 1
                c.submit(leader, p["cmd"])
                p["last_sent"] = c.now
        c.tick()
        self.leader_trace.append(c.leader())
        self.max_term = max(self.max_term, max(n.current_term for n in c.nodes.values()))
        committed = self._committed_ids()
        for req in [r for r in self.pending if r in committed]:
            self.done[req] = c.now - self.pending.pop(req)["first"]

    def run(self, ticks: int, send: bool = True):
        for _ in range(ticks):
            self.step(send)

    def duplicates(self) -> int:
        """Orders committed more than once (a re-sent order whose first copy also survived)."""
        best = max(self.c.nodes.values(), key=lambda n: n.commit_index)
        seen, dup = set(), 0
        for e in best.log[:best.commit_index]:
            if isinstance(e.command, dict) and "req" in e.command:
                dup += e.command["req"] in seen
                seen.add(e.command["req"])
        return dup

    def summary(self) -> dict:
        trace = self.leader_trace
        changes = sum(1 for a, b in zip(trace, trace[1:]) if b is not None and a != b)
        lat = sorted(self.done.values())
        return {
            "ticks": len(trace),
            "elections": self.c.elections,
            "leader_changes": changes,
            "ticks_without_leader_pct": round(100 * sum(t is None for t in trace) / max(1, len(trace)), 1),
            "max_term": self.max_term,
            "orders_sent": self.sent,
            "orders_committed": len(self.done),
            "orders_outstanding": len(self.pending),
            "resends": self.resends,
            "duplicate_commits": self.duplicates(),
            "latency_ticks_median": statistics.median(lat) if lat else None,
            "latency_ticks_p95": lat[int(0.95 * (len(lat) - 1))] if lat else None,
            "pre_votes_failed": self.c.pre_votes_failed,
            "votes_refused_by_stickiness": self.c.votes_refused_sticky,
            "safety": self.c.check_safety(),
        }
