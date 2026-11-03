"""
Raft consensus - tick-driven simulation (Regional Incident DB, Emergency Dispatch).

Implements the parts of Raft that matter for the security analysis:
  * leader election with randomised timeouts and the "up-to-date log" vote rule
  * log replication with consistency check / conflict truncation
  * commit only of current-term entries replicated on a majority
  * check-quorum: a leader that cannot reach a majority steps down (leader lease)
  * optional Pre-Vote + leader stickiness (Raft thesis s9.6) against disruptive candidates
  * timing-configuration validation (election timeout must dominate the heartbeat interval)
  * network partitions and per-node overload (for DoS experiments)
  * a safety checker (one leader per term, committed logs are prefixes of each other)

Messages are delivered synchronously within a tick when the link is up.
1 tick ~ 10 ms of wall-clock time.
"""
import random
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Callable, Optional


class NodeState(Enum):
    FOLLOWER = "follower"
    CANDIDATE = "candidate"
    LEADER = "leader"


@dataclass
class LogEntry:
    term: int
    command: Any


@dataclass
class RaftNode:
    node_id: str
    region: str = ""
    state: NodeState = NodeState.FOLLOWER
    current_term: int = 0
    voted_for: Optional[str] = None
    log: list = field(default_factory=list)
    commit_index: int = 0           # number of committed entries
    leader_id: Optional[str] = None
    elapsed: int = 0
    timeout: int = 0
    # leader state
    next_index: dict = field(default_factory=dict)
    match_index: dict = field(default_factory=dict)
    last_ack: dict = field(default_factory=dict)
    last_heartbeat_sent: int = -999
    last_leader_contact: int = -999  # tick this node last accepted an AppendEntries from a leader

    def last_index(self) -> int:
        return len(self.log)

    def last_term(self) -> int:
        return self.log[-1].term if self.log else 0


def _noop_log(node, term, event, detail):
    pass


class RaftCluster:
    def __init__(self, regions: dict[str, list[str]], election_timeout=(15, 30), heartbeat=3,
                 check_quorum: bool = True, seed: int = 0,
                 log: Callable[[str, int, str, dict], None] = _noop_log,
                 pre_vote: bool = False, validate_timing: bool = False, loss: float = 0.0):
        if validate_timing:
            validate_timing_config(election_timeout, heartbeat)
        self.rng = random.Random(seed)
        self.nodes: dict[str, RaftNode] = {}
        for region, ids in regions.items():
            for nid in ids:
                self.nodes[nid] = RaftNode(nid, region)
        self.n = len(self.nodes)
        self.election_timeout = election_timeout
        self.heartbeat = heartbeat
        self.check_quorum = check_quorum
        self.pre_vote = pre_vote
        self.loss = loss                        # per-message drop probability on every link
        self.loss_rng = random.Random(seed + 1)
        self.pre_votes_failed = 0
        self.votes_refused_sticky = 0
        self.log = log
        self.now = 0
        self.blocked: set[frozenset] = set()
        self.overloaded: set[str] = set()       # nodes that cannot send this tick (DoS)
        self.leaders_by_term: dict[int, set] = {}
        self.elections = 0
        for node in self.nodes.values():
            node.timeout = self._new_timeout()

    # -- helpers -------------------------------------------------------------
    def quorum(self) -> int:
        return self.n // 2 + 1

    def _new_timeout(self) -> int:
        return self.rng.randint(*self.election_timeout)

    def reachable(self, a: str, b: str) -> bool:
        if frozenset((a, b)) in self.blocked:
            return False
        return not (self.loss and self.loss_rng.random() < self.loss)

    def partition(self, *groups: list[str]):
        self.blocked = {frozenset((a, b)) for i, g in enumerate(groups) for h in groups[i + 1:]
                        for a in g for b in h}
        self.log("network", self.now, "partition", {"groups": [list(g) for g in groups]})

    def isolate(self, node_id: str):
        """Cut every link of one node (flapping NIC, routing fault)."""
        self.blocked |= {frozenset((node_id, o)) for o in self.nodes if o != node_id}
        self.log("network", self.now, "node_isolated", {"node": node_id})

    def reconnect(self, node_id: str):
        self.blocked = {b for b in self.blocked if node_id not in b}
        self.log("network", self.now, "node_reconnected", {"node": node_id})

    def heal(self):
        self.blocked = set()
        self.log("network", self.now, "partition_healed", {})

    def leader(self) -> Optional[str]:
        """The leader with the highest term (what a client would find)."""
        leaders = [n for n in self.nodes.values() if n.state == NodeState.LEADER]
        return max(leaders, key=lambda n: n.current_term).node_id if leaders else None

    def leaders(self) -> list[str]:
        return [n.node_id for n in self.nodes.values() if n.state == NodeState.LEADER]

    def _step_down(self, node: RaftNode, term: int, reason: str):
        was_leader = node.state == NodeState.LEADER
        if term > node.current_term:
            node.current_term = term
            node.voted_for = None
        node.state = NodeState.FOLLOWER
        node.elapsed = 0
        if was_leader:
            self.log(node.node_id, node.current_term, "step_down", {"reason": reason})

    # -- RPC handlers ----------------------------------------------------------
    def _heard_from_leader_recently(self, node: RaftNode) -> bool:
        return self.now - node.last_leader_contact < self.election_timeout[0]

    def _handle_pre_vote(self, voter: RaftNode, term, last_idx, last_term) -> bool:
        """Would voter grant a vote at `term`? Changes no state (Pre-Vote)."""
        if term <= voter.current_term:
            return False
        if voter.state == NodeState.LEADER or self._heard_from_leader_recently(voter):
            return False
        return (last_term > voter.last_term() or
                (last_term == voter.last_term() and last_idx >= voter.last_index()))

    def _handle_request_vote(self, voter: RaftNode, term, cand_id, last_idx, last_term):
        if term < voter.current_term:
            return voter.current_term, False
        if self.pre_vote and term > voter.current_term and (
                voter.state == NodeState.LEADER or self._heard_from_leader_recently(voter)):
            # Leader stickiness: a live leader exists, so ignore the disruptive candidate's term.
            self.votes_refused_sticky += 1
            return voter.current_term, False
        if term > voter.current_term:
            self._step_down(voter, term, "higher_term_in_vote_request")
        up_to_date = (last_term > voter.last_term() or
                      (last_term == voter.last_term() and last_idx >= voter.last_index()))
        if voter.voted_for in (None, cand_id) and up_to_date:
            voter.voted_for = cand_id
            voter.elapsed = 0
            return voter.current_term, True
        return voter.current_term, False

    def _handle_append(self, f: RaftNode, term, leader_id, prev_idx, prev_term, entries, leader_commit):
        if term < f.current_term:
            return f.current_term, False
        if term > f.current_term or f.state != NodeState.FOLLOWER:
            self._step_down(f, term, "append_from_current_leader")
        f.leader_id = leader_id
        f.elapsed = 0
        f.last_leader_contact = self.now
        if prev_idx > len(f.log) or (prev_idx > 0 and f.log[prev_idx - 1].term != prev_term):
            return f.current_term, False
        for i, e in enumerate(entries):
            idx = prev_idx + i
            if idx < len(f.log):
                if f.log[idx].term != e.term:
                    dropped = len(f.log) - idx
                    del f.log[idx:]
                    self.log(f.node_id, f.current_term, "log_truncated",
                             {"from_index": idx + 1, "dropped_entries": dropped})
                    f.log.append(e)
            else:
                f.log.append(e)
        new_commit = min(leader_commit, prev_idx + len(entries))
        if new_commit > f.commit_index:
            f.commit_index = new_commit
        return f.current_term, True

    # -- node actions ----------------------------------------------------------
    def _start_election(self, node: RaftNode):
        if self.pre_vote:
            pre = 1 + sum(self._handle_pre_vote(p, node.current_term + 1, node.last_index(), node.last_term())
                          for p in self.nodes.values()
                          if p is not node and self.reachable(node.node_id, p.node_id))
            if pre < self.quorum():
                self.pre_votes_failed += 1
                node.elapsed = 0
                node.timeout = self._new_timeout()
                self.log(node.node_id, node.current_term, "pre_vote_failed",
                         {"pre_votes": pre, "required": self.quorum()})
                return
        node.state = NodeState.CANDIDATE
        node.current_term += 1
        node.voted_for = node.node_id
        node.elapsed = 0
        node.timeout = self._new_timeout()
        self.elections += 1
        votes = 1
        for peer in self.nodes.values():
            if peer is node or not self.reachable(node.node_id, peer.node_id):
                continue
            term, granted = self._handle_request_vote(peer, node.current_term, node.node_id,
                                                      node.last_index(), node.last_term())
            if term > node.current_term:
                self._step_down(node, term, "higher_term_in_vote_reply")
                return
            votes += granted
        if votes >= self.quorum():
            self._become_leader(node, votes)
        else:
            self.log(node.node_id, node.current_term, "election_failed",
                     {"votes": votes, "required": self.quorum()})
            node.state = NodeState.FOLLOWER

    def _become_leader(self, node: RaftNode, votes: int):
        node.state = NodeState.LEADER
        node.leader_id = node.node_id
        self.leaders_by_term.setdefault(node.current_term, set()).add(node.node_id)
        for peer in self.nodes:
            node.next_index[peer] = len(node.log)
            node.match_index[peer] = 0
            node.last_ack[peer] = self.now
        node.log.append(LogEntry(node.current_term, {"noop": True}))  # commits earlier-term entries
        self.log(node.node_id, node.current_term, "leader_elected",
                 {"votes": votes, "region": node.region})
        self._broadcast_append(node)

    def _broadcast_append(self, leader: RaftNode):
        leader.last_heartbeat_sent = self.now
        if leader.node_id in self.overloaded:
            return
        for peer in self.nodes.values():
            if peer is leader or not self.reachable(leader.node_id, peer.node_id):
                continue
            prev = leader.next_index[peer.node_id]
            prev_term = leader.log[prev - 1].term if prev > 0 else 0
            entries = leader.log[prev:]
            term, ok = self._handle_append(peer, leader.current_term, leader.node_id, prev, prev_term,
                                           entries, leader.commit_index)
            if term > leader.current_term:
                self._step_down(leader, term, "higher_term_in_append_reply")
                return
            leader.last_ack[peer.node_id] = self.now
            if ok:
                leader.match_index[peer.node_id] = prev + len(entries)
                leader.next_index[peer.node_id] = prev + len(entries)
            else:
                leader.next_index[peer.node_id] = max(0, prev - 1)
        self._advance_commit(leader)

    def _advance_commit(self, leader: RaftNode):
        for idx in range(len(leader.log), leader.commit_index, -1):
            if leader.log[idx - 1].term != leader.current_term:
                break
            replicas = 1 + sum(1 for p, m in leader.match_index.items() if p != leader.node_id and m >= idx)
            if replicas >= self.quorum():
                start = leader.commit_index
                leader.commit_index = idx
                for pos in range(start, idx):
                    e = leader.log[pos]
                    if not (isinstance(e.command, dict) and e.command.get("noop")):
                        self.log(leader.node_id, leader.current_term, "commit",
                                 {"index": pos + 1, "command": e.command, "replicas": replicas})
                break

    # -- public API ------------------------------------------------------------
    def tick(self):
        self.now += 1
        for node in list(self.nodes.values()):
            if node.state == NodeState.LEADER:
                if self.check_quorum:
                    window = self.election_timeout[0]
                    fresh = 1 + sum(1 for p, t in node.last_ack.items()
                                    if p != node.node_id and self.now - t <= window)
                    if fresh < self.quorum():
                        self._step_down(node, node.current_term, "check_quorum_lost_majority")
                        continue
                if self.now - node.last_heartbeat_sent >= self.heartbeat:
                    self._broadcast_append(node)
            else:
                node.elapsed += 1
                if node.elapsed >= node.timeout:
                    self._start_election(node)

    def run(self, ticks: int):
        for _ in range(ticks):
            self.tick()

    def submit(self, node_id: str, command: Any) -> Optional[int]:
        """Client write to node_id. Returns the log index if node is a leader, else None."""
        node = self.nodes[node_id]
        if node.state != NodeState.LEADER:
            return None
        node.log.append(LogEntry(node.current_term, command))
        return len(node.log)

    def read(self, node_id: str) -> Optional[list]:
        """Local read of committed commands at node_id if it believes it is leader (no read-index)."""
        node = self.nodes[node_id]
        if node.state != NodeState.LEADER:
            return None
        return [e.command for e in node.log[:node.commit_index]
                if not (isinstance(e.command, dict) and e.command.get("noop"))]

    def is_committed(self, command: Any) -> bool:
        return any(e.command == command for n in self.nodes.values() for e in n.log[:n.commit_index])

    def check_safety(self) -> dict:
        two_leaders = {t: sorted(l) for t, l in self.leaders_by_term.items() if len(l) > 1}
        divergent = []
        nodes = list(self.nodes.values())
        for i, a in enumerate(nodes):
            for b in nodes[i + 1:]:
                k = min(a.commit_index, b.commit_index)
                if [(e.term, repr(e.command)) for e in a.log[:k]] != [(e.term, repr(e.command)) for e in b.log[:k]]:
                    divergent.append((a.node_id, b.node_id))
        return {"two_leaders_same_term": two_leaders, "divergent_committed_logs": divergent,
                "safe": not two_leaders and not divergent}

    def get_state(self) -> dict:
        return {
            "tick": self.now,
            "leader": self.leader(),
            "nodes": {nid: {"state": n.state.value, "term": n.current_term, "log_len": len(n.log),
                            "commit_index": n.commit_index, "region": n.region}
                      for nid, n in self.nodes.items()},
            "elections": self.elections,
        }


class TimingConfigError(ValueError):
    pass


def validate_timing_config(election_timeout: tuple, heartbeat: int, min_ratio: int = 5, min_spread: int = 5):
    """Raft's timing requirement: broadcastTime << electionTimeout. Reject configs that break it.

    * the smallest election timeout must be at least `min_ratio` heartbeat intervals, so a follower
      sees several heartbeats before it may suspect the leader;
    * the randomisation window must be wide enough that two followers rarely time out together.
    """
    lo, hi = election_timeout
    problems = []
    if lo < min_ratio * heartbeat:
        problems.append(f"election timeout min {lo} < {min_ratio} x heartbeat {heartbeat}")
    if hi - lo < min_spread:
        problems.append(f"randomisation window {hi - lo} < {min_spread} ticks")
    if problems:
        raise TimingConfigError("; ".join(problems))
    return True
