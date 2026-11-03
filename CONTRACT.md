### SECURITY DOMAINS
- Operational
- Oversight
- Intelligence

### TRUST BOUNDARIES
- Operational
- Oversight
- Intelligence
- User
- Researcher

### CONFIDENTIALITY LABELS (low → high)
PUBLIC < OFFICIAL < CONFIDENTIAL < SECRET < TOP SECRET

### INTEGRITY LEVELS (low → high)
Unverified < Operational < Command < Audit
  - caller-supplied data          → Unverified
  - incidents, dispatch           → Operational (Critical incidents → Command)
  - intelligence reports          → Command
  - audit records                 → Audit

| ROLES | clearance | integrity |
| --- | --- | --- |
| Paramedic | OFFICIAL | Operational |
| Fire Officer | OFFICIAL | Operational |
| Dispatcher | OFFICIAL | Operational   (added: not in responders.json) |
| Police Officer | SECRET | Operational |
| Intel Analyst | per record | Operational   (SECRET or TOP SECRET) |
| Regional Cmdr | TOP SECRET | Command |
| National Cmdr | TOP SECRET | Command |
| Auditor | SECRET | Audit (read-only; only the system writes audit) |

### PROTOCOL PER SUBSYSTEM
- Audit Log, Intelligence Distribution    → BFT
- Incident DB, Dispatch                   → Raft
- Resource Allocation                     → Paxos

### HANDOFF BETWEEN C AND D
Part C writes classified/<dataset>.json: each record gets
  "_label", "_integrity", "_reasons" (list of strings)
Part D reads only those fields. Until C is ready, D hard-codes them for 5 records.

### EXPERIMENT LOGS
experiments/<protocol>-<attack>/
  run.py · log.jsonl · README.md (assumption violated / change made /
  behaviour observed / properties affected / mitigation)
log line: {"t":..., "node":..., "term_or_round":..., "event":..., "detail":...}
