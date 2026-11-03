#!/usr/bin/env python3
"""
Retention, archiving and secure destruction (Part C3 / C4).

Lifecycle:  ACTIVE --(active period ends)--> ARCHIVED --(retention ends)--> DESTROYED | REVIEW
            plus field-level minimisation (caller PII redacted 30 days after the incident)
            and LEGAL HOLD, which blocks destruction until released.

Mechanisms
  * Every record is stored encrypted (AES-256-GCM) under its own data key held in a KeyStore
    (stands in for a KMS/HSM). The archive tier is compressed then re-encrypted under a new key.
  * Secure destruction = crypto-shredding: the record's data key is destroyed and its ciphertext
    deleted, so any copy left in backups or replicas is unreadable. A destruction certificate
    (record id, label, ciphertext digest, rule, authoriser) is written to the governance log.
  * Audit records are never deleted outright: their payload is shredded but the entry digest stays,
    so the hash-chained audit trail still verifies (tombstone).
  * The governance log is itself hash-chained; `verify_chain` detects any rewritten entry.
  * Archive reads go through the Part D policy engine (ACM + BLP + Biba) and an archive-role check.

Retention periods are set per dataset and classification (RETENTION_SCHEDULE). Where the supplied
data has no date (intelligence, responders) the snapshot date is used, an assumption the report states.
"""
import copy
import hashlib
import json
import os
import zlib
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from nerp.models import Action, Classification, Role, load_users

SNAPSHOT_DATE = datetime(2026, 11, 3, tzinfo=timezone.utc)
YEAR = timedelta(days=365)
PII_FIELDS = {"incidents": ["callerName", "callerPhone"]}
PII_MINIMISE_AFTER = timedelta(days=30)
ARCHIVE_ROLES = {Role.AUDITOR, Role.REGIONAL_CMDR, Role.NATIONAL_CMDR}
DISPOSAL_ROLES = {Role.AUDITOR}            # destruction is authorised by Oversight, not by operations

# (active years, total retention years, end action, basis). End action: destroy | review | tombstone
RETENTION_SCHEDULE = {
    "incidents": {
        "OFFICIAL":     (1, 7, "destroy", "Limitation Act 1980: 6-year claim window + 1 year margin"),
        "CONFIDENTIAL": (1, 10, "destroy", "Caller personal data, often with casualty/health content: aligned "
                                           "with NHS Records Management Code (ambulance records, adults: 10 "
                                           "years), which exceeds the Limitation Act 6-year window"),
        "SECRET":       (2, 20, "review", "Security incidents may feed investigations/inquiries: review at "
                                          "20 years (Public Records Act transfer point), never auto-destroy"),
    },
    "dispatch": "inherit:incidents",       # destroyed together with its incident (referential integrity)
    "intelligence": {
        "OFFICIAL":     (1, 6, "review", "MoPI-style review: retain only while necessary and proportionate"),
        "CONFIDENTIAL": (1, 6, "review", "MoPI-style review at 6 years"),
        "SECRET":       (2, 10, "review", "Review at 10 years; extended while the threat remains live"),
        "TOP_SECRET":   (2, 25, "review", "Review at 25 years; national-security retention or transfer"),
    },
    "audit": {
        "CONFIDENTIAL": (1, 7, "tombstone", "Minimum 7 years immutable; payload shredded, digest kept"),
        "SECRET":       (1, 7, "tombstone", "As CONFIDENTIAL, but never before the referenced record's "
                                            "own retention ends (access history lives as long as the data)"),
    },
    "responders": {
        "OFFICIAL":     (6, 6, "review", "Employment record: annual review; employment end date not in "
                                         "dataset, so held for review at 6 years"),
        "CONFIDENTIAL": (6, 6, "review", "As OFFICIAL"),
        "SECRET":       (6, 6, "review", "As CONFIDENTIAL; review also checks the linked security incident's "
                                         "legal hold before disposal"),
    },
}
ID_FIELD = {"incidents": "incidentId", "dispatch": "dispatchId", "intelligence": "reportId",
            "audit": "eventId", "responders": "responderId"}


class RetentionError(PermissionError):
    pass


# --------------------------------------------------------------------------------------------------
class KeyStore:
    """Per-record data keys. Destroying a key makes every copy of the ciphertext unreadable."""
    def __init__(self):
        self._keys: dict[str, bytes] = {}
        self.destroyed: set[str] = set()

    def new(self, key_id: str) -> bytes:
        self._keys[key_id] = AESGCM.generate_key(bit_length=256)
        return self._keys[key_id]

    def get(self, key_id: str) -> bytes:
        if key_id in self.destroyed:
            raise KeyError(f"key {key_id} destroyed (crypto-shredded)")
        return self._keys[key_id]

    def destroy(self, key_id: str):
        k = self._keys.pop(key_id, None)
        if k is not None:
            # best-effort overwrite of the in-memory copy (a real HSM zeroises the key)
            bytearray(k)[:] = b"\x00" * len(k)
        self.destroyed.add(key_id)


class GovernanceLog:
    """Append-only, hash-chained log of every retention action and refusal."""
    def __init__(self, path: Path | None = None):
        self.path = path                    # None = in-memory only
        self.entries: list[dict] = []
        if path:
            path.unlink(missing_ok=True)

    def append(self, event: str, **detail) -> dict:
        prev = self.entries[-1]["hash"] if self.entries else "0" * 64
        body = {"seq": len(self.entries), "event": event, "detail": detail, "prev": prev}
        body["hash"] = hashlib.sha256(json.dumps(body, sort_keys=True, default=str).encode()).hexdigest()
        self.entries.append(body)
        if self.path:
            with self.path.open("a") as f:
                f.write(json.dumps(body, default=str) + "\n")
        return body

    def verify_chain(self, entries: list[dict] | None = None) -> bool:
        prev = "0" * 64
        for e in entries or self.entries:
            body = {k: v for k, v in e.items() if k != "hash"}
            if body["prev"] != prev:
                return False
            if hashlib.sha256(json.dumps(body, sort_keys=True, default=str).encode()).hexdigest() != e["hash"]:
                return False
            prev = e["hash"]
        return True


@dataclass
class StoredRecord:
    dataset: str
    record_id: str
    label: str
    integrity: str
    created: datetime
    tier: str = "active"                  # active | archived | destroyed | review
    key_id: str = ""
    nonce: bytes = b""
    ciphertext: bytes = b""
    compressed: bool = False
    legal_hold: str | None = None
    minimised: bool = False
    rule: tuple = ()
    archive_at: datetime | None = None
    end_at: datetime | None = None
    tombstone_digest: str | None = None
    links: dict = field(default_factory=dict)


# --------------------------------------------------------------------------------------------------
class RecordStore:
    def __init__(self, classified: dict, log: GovernanceLog, min_retention_years: int | None = None):
        self.keys = KeyStore()
        self.log = log
        self.records: dict[str, StoredRecord] = {}
        self.min_years = min_retention_years
        self.version = 0
        incidents = {r["incidentId"]: r for r in classified["incidents"]}
        for ds, recs in classified.items():
            for r in recs:
                rid = r[ID_FIELD[ds]]
                created = self._created(ds, r, incidents)
                sr = StoredRecord(ds, rid, r["_label"], r["_integrity"], created)
                if ds == "dispatch":
                    sr.links["incident"] = r["incidentId"]
                if ds == "audit":
                    sr.links["resource"] = r["resource"]
                self._encrypt(sr, r)
                self.records[f"{ds}/{rid}"] = sr
        for sr in self.records.values():
            self._schedule(sr)

    # -- crypto --------------------------------------------------------------------------------------
    def _encrypt(self, sr: StoredRecord, payload: dict, compress: bool = False):
        self.version += 1
        sr.key_id = f"{sr.dataset}/{sr.record_id}@v{self.version}"
        key = self.keys.new(sr.key_id)
        data = json.dumps(payload, sort_keys=True).encode()
        if compress:
            data = zlib.compress(data, 9)
        sr.nonce = os.urandom(12)
        sr.ciphertext = AESGCM(key).encrypt(sr.nonce, data, sr.key_id.encode())
        sr.compressed = compress

    def _decrypt(self, sr: StoredRecord) -> dict:
        data = AESGCM(self.keys.get(sr.key_id)).decrypt(sr.nonce, sr.ciphertext, sr.key_id.encode())
        return json.loads(zlib.decompress(data) if sr.compressed else data)

    # -- policy --------------------------------------------------------------------------------------
    @staticmethod
    def _created(ds, r, incidents) -> datetime:
        ts = r.get("timestamp") or (incidents.get(r.get("incidentId"), {}).get("timestamp"))
        if ts:
            return datetime.fromisoformat(ts.replace("Z", "+00:00"))
        return SNAPSHOT_DATE

    def rule_for(self, sr: StoredRecord) -> tuple:
        sched = RETENTION_SCHEDULE[sr.dataset]
        if isinstance(sched, str):                         # inherit from the linked incident
            parent = self.records[f"incidents/{sr.links['incident']}"]
            return self.rule_for(parent) if not parent.rule else parent.rule
        return sched[sr.label]

    def _schedule(self, sr: StoredRecord):
        active, total, action, basis = self.rule_for(sr)
        if self.min_years and total < self.min_years:
            basis = f"{basis} | extended to {self.min_years}y by regulation"
            total = self.min_years
        sr.rule = (active, total, action, basis)
        sr.archive_at = sr.created + active * YEAR
        sr.end_at = sr.created + total * YEAR
        if sr.dataset == "audit" and sr.links["resource"].split("-")[0] in ("INT", "INC"):
            ref_ds = "intelligence" if sr.links["resource"].startswith("INT") else "incidents"
            ref = self.records.get(f"{ref_ds}/{sr.links['resource']}")
            if ref:
                ref_end = ref.created + self.rule_for(ref)[1] * YEAR
                sr.end_at = max(sr.end_at, ref_end + YEAR)   # keep the access history as long as the data

    # -- legal hold ----------------------------------------------------------------------------------
    def place_hold(self, key: str, reason: str, by: str):
        self.records[key].legal_hold = reason
        self.log.append("legal_hold_placed", record=key, reason=reason, by=by)

    def release_hold(self, key: str, by: str):
        self.records[key].legal_hold = None
        self.log.append("legal_hold_released", record=key, by=by)

    # -- lifecycle actions ---------------------------------------------------------------------------
    def minimise(self, sr: StoredRecord, now: datetime):
        payload = self._decrypt(sr)
        removed = [f for f in PII_FIELDS.get(sr.dataset, []) if payload.get(f) is not None]
        for f in removed:
            payload[f] = None
        old_key = sr.key_id
        self._encrypt(sr, payload, compress=sr.compressed)
        self.keys.destroy(old_key)                      # the old ciphertext (with PII) is now unreadable
        sr.minimised = True
        self.log.append("pii_minimised", record=f"{sr.dataset}/{sr.record_id}", fields=removed,
                        at=now.date(), basis="UK GDPR Art 5(1)(c),(e): no operational need after call-back window")

    def archive(self, sr: StoredRecord, now: datetime):
        payload = self._decrypt(sr)
        before = len(sr.ciphertext)
        old_key = sr.key_id
        self._encrypt(sr, payload, compress=True)
        self.keys.destroy(old_key)
        sr.tier = "archived"
        self.log.append("archived", record=f"{sr.dataset}/{sr.record_id}", label=sr.label, at=now.date(),
                        bytes_before=before, bytes_after=len(sr.ciphertext))

    def destroy(self, sr: StoredRecord, now: datetime, by: Role, reason: str):
        key = f"{sr.dataset}/{sr.record_id}"
        if by not in DISPOSAL_ROLES:
            self.log.append("destruction_refused", record=key, by=by.value, why="role not authorised for disposal")
            raise RetentionError(f"{by.value} may not authorise destruction")
        if sr.legal_hold:
            self.log.append("destruction_refused", record=key, by=by.value, why=f"legal hold: {sr.legal_hold}")
            raise RetentionError(f"{key} is under legal hold")
        if now < sr.end_at:
            self.log.append("destruction_refused", record=key, by=by.value,
                            why=f"retention runs until {sr.end_at.date()}")
            raise RetentionError(f"{key} retained until {sr.end_at.date()}")
        dependants = [k for k, d in self.records.items()
                      if d.tier not in ("destroyed",) and d.links.get("incident") == sr.record_id
                      and d is not sr and d.dataset == "dispatch"]
        cert = {"record": key, "label": sr.label, "ciphertext_sha256": hashlib.sha256(sr.ciphertext).hexdigest(),
                "key_id": sr.key_id, "rule": sr.rule[3], "authorised_by": by.value, "reason": reason,
                "at": now.date(), "method": "crypto-shred (key destroyed) + ciphertext deleted"}
        if sr.rule[2] == "tombstone":
            sr.tombstone_digest = cert["ciphertext_sha256"]
            cert["method"] = "tombstone: payload crypto-shredded, digest retained for chain verification"
        self.keys.destroy(sr.key_id)
        sr.ciphertext, sr.nonce = b"", b""
        sr.tier = "destroyed"
        self.log.append("destroyed", **cert)
        for d in dependants:                               # dispatch rows go with their incident
            self.destroy(self.records[d], now, by, f"dependent of {key}")

    def read_archived(self, key: str, user, engine) -> dict:
        sr = self.records[key]
        res = engine.evaluate_record(user, sr.dataset, {"_label": sr.label, "_integrity": sr.integrity},
                                     Action.READ)
        allowed = user.role in ARCHIVE_ROLES and res.decision.value == "grant"
        self.log.append("archive_read" if allowed else "archive_read_refused", record=key,
                        user=f"{user.name} ({user.role.value})",
                        why=None if allowed else ("not an archive role" if user.role not in ARCHIVE_ROLES
                                                  else res.reason))
        if not allowed:
            why = "not an archive role" if user.role not in ARCHIVE_ROLES else res.reason
            raise RetentionError(f"{user.role.value} may not read archived {key}: {why}")
        return self._decrypt(sr)

    # -- enforcement ---------------------------------------------------------------------------------
    def enforce(self, now: datetime) -> dict:
        """Apply every action due at `now`. Returns counts of what happened."""
        done = {"pii_minimised": 0, "archived": 0, "destroyed": 0, "queued_for_review": 0,
                "blocked_by_legal_hold": 0, "audit_deferred_referenced_record_live": 0}
        for sr in list(self.records.values()):
            if sr.tier == "destroyed":
                continue
            if (not sr.minimised and sr.dataset in PII_FIELDS and now >= sr.created + PII_MINIMISE_AFTER
                    and sr.legal_hold is None):
                self.minimise(sr, now)
                done["pii_minimised"] += 1
            if sr.tier == "active" and now >= sr.archive_at:
                self.archive(sr, now)
                done["archived"] += 1
            if now >= sr.end_at and sr.tier in ("active", "archived"):
                if sr.legal_hold:
                    done["blocked_by_legal_hold"] += 1
                    continue
                if sr.dataset == "audit" and self._referenced_live(sr):
                    done["audit_deferred_referenced_record_live"] += 1
                    continue
                if sr.rule[2] == "review":
                    sr.tier = "review"
                    self.log.append("queued_for_review", record=f"{sr.dataset}/{sr.record_id}",
                                    label=sr.label, basis=sr.rule[3], at=now.date())
                    done["queued_for_review"] += 1
                elif sr.dataset != "dispatch":            # dispatch is destroyed with its incident
                    self.destroy(sr, now, Role.AUDITOR, "scheduled end of retention")
                    done["destroyed"] += 1
        return done

    def _referenced_live(self, sr: StoredRecord) -> bool:
        res = sr.links.get("resource", "")
        ds = "intelligence" if res.startswith("INT-") else "incidents" if res.startswith("INC-") else None
        ref = self.records.get(f"{ds}/{res}") if ds else None
        return ref is not None and ref.tier != "destroyed"

    def state(self) -> dict:
        tiers: dict = {}
        for sr in self.records.values():
            t = tiers.setdefault(sr.tier, {})
            t[sr.dataset] = t.get(sr.dataset, 0) + 1
        return {"tiers": tiers,
                "bytes": {t: sum(len(s.ciphertext) for s in self.records.values() if s.tier == t)
                          for t in ("active", "archived", "review")},
                "legal_holds": sorted(k for k, s in self.records.items() if s.legal_hold)}

    def storage_record_years(self) -> float:
        return round(sum((s.end_at - s.created).days / 365 for s in self.records.values()), 1)


# --------------------------------------------------------------------------------------------------
def _demo(out_dir: Path, classified: dict) -> dict:
    from nerp.policy_engine import PolicyEngine
    log = GovernanceLog(out_dir / "governance_log.jsonl")
    store = RecordStore(classified, log)
    users = {u.role: u for u in load_users()}
    engine = PolicyEngine()

    # Legal holds: live counter-terrorism cases (dispatch still In Progress / Pending)
    for d in classified["dispatch"]:
        if d["status"] in ("In Progress", "Pending") and d["_label"] == "SECRET":
            store.place_hold(f"incidents/{d['incidentId']}", f"live CT case ({d['dispatchId']} {d['status']})",
                             by="National Commander")

    timeline = []
    m = timedelta(days=30)                 # checkpoints sit a month after each anniversary
    checkpoints = [("day 0", timedelta(0)), ("+31 days", timedelta(days=31)), ("+2 years", 2 * YEAR + m),
                   ("+8 years", 8 * YEAR + m), ("+11 years", 11 * YEAR + m), ("+21 years", 21 * YEAR + m),
                   ("+26 years", 26 * YEAR + m)]
    probes = {}
    for name, delta in checkpoints:
        now = SNAPSHOT_DATE + delta
        actions = store.enforce(now)
        timeline.append({"checkpoint": name, "date": now.date().isoformat(), "actions": actions, **store.state()})
        if name == "+31 days":
            inc = store.records["incidents/INC-002"]
            probes["pii_after_31_days"] = {k: store._decrypt(inc)[k] for k in ("callerName", "callerPhone")}
        if name == "+2 years":
            probes["archive_read_paramedic"] = _try(lambda: store.read_archived(
                "incidents/INC-002", users[Role.PARAMEDIC], engine))
            probes["archive_read_auditor_audit_record"] = _try(lambda: store.read_archived(
                "audit/AUD-014", users[Role.AUDITOR], engine))
            probes["archive_read_regional_cmdr_secret_intel"] = _try(lambda: store.read_archived(
                "intelligence/INT-001", users[Role.REGIONAL_CMDR], engine))
            probes["archive_read_regional_cmdr_incident"] = _try(lambda: store.read_archived(
                "incidents/INC-002", users[Role.REGIONAL_CMDR], engine))
            probes["early_destroy_audit_by_commander"] = _try(lambda: store.destroy(
                store.records["audit/AUD-014"], now, Role.REGIONAL_CMDR, "tidy-up"))
            probes["early_destroy_audit_by_auditor"] = _try(lambda: store.destroy(
                store.records["audit/AUD-014"], now, Role.AUDITOR, "tidy-up"))
        if name == "+21 years":
            probes["destroy_under_legal_hold"] = _try(lambda: store.destroy(
                store.records["incidents/INC-010"], now, Role.AUDITOR, "end of retention"))
        if name == "+11 years":
            sr = store.records["incidents/INC-002"]
            probes["read_destroyed_record"] = _try(lambda: store._decrypt(sr))
            probes["destroyed_key_id_still_in_keystore"] = sr.key_id in store.keys._keys
            probes["INC-002_dispatch_D002_tier"] = store.records["dispatch/D002"].tier

    # Tamper-evidence of the governance log itself
    forged = copy.deepcopy(log.entries)
    victim = next(e for e in forged if e["event"] == "destroyed")
    victim["detail"]["authorised_by"] = "auditor (forged)"
    integrity = {"governance_log_entries": len(log.entries), "chain_valid": log.verify_chain(),
                 "forged_copy_detected": not log.verify_chain(forged)}
    return {"timeline": timeline, "probes": probes, "log_integrity": integrity,
            "storage_record_years": store.storage_record_years()}


def _try(fn):
    try:
        r = fn()
        return {"allowed": True, "result": r if isinstance(r, (dict, str, type(None))) else str(r)}
    except (RetentionError, KeyError, Exception) as e:
        return {"allowed": False, "error": f"{type(e).__name__}: {e}"}


def regulation_impact(classified: dict, years: int = 20) -> dict:
    """Part E: what changes if every record must be kept for `years` years."""
    base = RecordStore(classified, GovernanceLog())
    reg = RecordStore(classified, GovernanceLog(), min_retention_years=years)
    extended = {}
    for k, a in base.records.items():
        b = reg.records[k]
        if b.end_at > a.end_at:
            key = f"{a.dataset}/{a.label}"
            extended[key] = extended.get(key, 0) + 1
    return {"years": years, "records_with_longer_retention": extended,
            "record_years_before": base.storage_record_years(), "record_years_after": reg.storage_record_years(),
            "conflicts": [
                "Caller PII: 20-year retention of the whole record conflicts with UK GDPR storage limitation; "
                "the field-level 30-day minimisation still applies unless the regulation names PII explicitly.",
                "Data keys must stay recoverable for 20 years (HSM lifecycle, key escrow, crypto agility).",
                "Intelligence 'review' rules become 'retain at least 20 years': review can no longer dispose early.",
            ]}


def schedule_table() -> list[dict]:
    rows = []
    for ds, sched in RETENTION_SCHEDULE.items():
        if isinstance(sched, str):
            rows.append({"dataset": ds, "classification": "inherits", "active_years": "-", "retention_years": "-",
                         "end_action": "destroyed with linked incident", "basis": sched})
            continue
        for label, (a, t, act, basis) in sched.items():
            rows.append({"dataset": ds, "classification": label, "active_years": a, "retention_years": t,
                         "end_action": act, "basis": basis})
    rows.append({"dataset": "incidents", "classification": "field: callerName, callerPhone", "active_years": "30 days",
                 "retention_years": "30 days", "end_action": "redact (re-encrypt, old key shredded)",
                 "basis": "UK GDPR data minimisation"})
    return rows


def run() -> dict:
    from nerp.information_flow import load_classified
    classified = {d: load_classified(d) for d in ID_FIELD}
    out_dir = Path(__file__).parent / "experiments" / "retention"
    out_dir.mkdir(parents=True, exist_ok=True)
    result = {"schedule": schedule_table(), "enforcement": _demo(out_dir, classified),
              "regulation_20y": regulation_impact(classified, 20)}
    (Path(__file__).parent / "experiments" / "retention_evidence.json").write_text(
        json.dumps(result, indent=2, default=str))
    tl = result["enforcement"]["timeline"]
    for t in tl:
        print(f"[Part C4] {t['checkpoint']:>10} {t['date']}: {t['actions']} -> tiers {t['tiers']}")
    li = result["enforcement"]["log_integrity"]
    print(f"[Part C4] governance log: {li['governance_log_entries']} entries, chain valid={li['chain_valid']}, "
          f"forgery detected={li['forged_copy_detected']}")
    return result


if __name__ == "__main__":
    import sys
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
    r = run()
    print(json.dumps(r["enforcement"]["probes"], indent=2, default=str))
