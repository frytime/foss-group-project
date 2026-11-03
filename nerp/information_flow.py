"""
Information Flow Engine (Part C) - Classifies records and writes classified datasets for Part D handoff.
Each record gets: _label (Classification), _integrity (Integrity), _reasons (list of strings)
"""
import json
import hashlib
import re
from datetime import datetime
from pathlib import Path
from typing import Any

from nerp.models import Classification, Integrity, load_all, parse_classification


# ---------------------------------------------------------------------------
# Part C classification rules (CONTRACT.md)
#   Labels:    PUBLIC < OFFICIAL < CONFIDENTIAL < SECRET < TOP SECRET
#   Integrity: caller-supplied data -> UNVERIFIED (field level)
#              incidents, dispatch -> OPERATIONAL (Critical incidents -> COMMAND)
#              intelligence        -> COMMAND
#              audit               -> AUDIT
# Each classifier returns (label, integrity, reasons, field_integrity).
# The label is the highest floor any rule sets ("high-water mark").
# ---------------------------------------------------------------------------

CALLER_FIELDS = ["callerName", "callerPhone"]
SECURITY_INCIDENT_TYPES = {"Terrorism Threat", "Suspicious Package"}
SAFEGUARDING_INCIDENT_TYPES = {"Missing Person"}          # concerns a potentially vulnerable person
KNOWN_INCIDENT_TYPES = SECURITY_INCIDENT_TYPES | SAFEGUARDING_INCIDENT_TYPES | {
    "Road Traffic Collision", "Fire", "Medical Emergency", "Flooding", "Chemical Spill",
    "Building Collapse", "Public Disorder"}
COMMAND_ROLES = {"Regional Commander", "National Commander", "Intelligence Analyst", "Auditor"}
SECURITY_UNITS = ("Counter Terror", "Explosives")          # unit names that reveal CT response posture
HIGH_RISK_AUDIT_ACTIONS = {"Modified Classification", "Exported Report"}   # insider-abuse indicators (T3)
# Words in an intelligence summary that indicate national-security content (C2 content analysis)
NATSEC_INDICATORS = re.compile(r"\b(attack|extremis\w*|terror\w*|sabotage|hostile|weapon\w*)\b", re.I)

# Default label per dataset before any record-specific rule; "raised" = above this baseline
BASELINE = {
    "incidents": Classification.CONFIDENTIAL,
    "responders": Classification.CONFIDENTIAL,
    "intelligence": Classification.SECRET,     # typical marking; lower originator markings are kept
    "dispatch": Classification.OFFICIAL,
    "audit": Classification.CONFIDENTIAL,
}

# Raw records are needed by some rules (dispatch/audit inherit from what they reference)
_RAW_CACHE: dict = {}


def _raw(dataset: str) -> dict:
    if not _RAW_CACHE:
        names = ["incidents", "responders", "intelligence", "dispatch", "audit"]
        key = {"incidents": "incidentId", "responders": "responderId", "intelligence": "reportId",
               "dispatch": "dispatchId", "audit": "eventId"}
        for n, recs in zip(names, load_all()):
            _RAW_CACHE[n] = {r[key[n]]: r for r in recs}
    return _RAW_CACHE[dataset]


def _raise(current: Classification, floor: Classification) -> Classification:
    return floor if floor.value > current.value else current


def classify_incident(r: dict, review: list | None = None):
    review = [] if review is None else review
    label = BASELINE["incidents"]
    reasons = ["CONFIDENTIAL (baseline): caller name and phone number are personal data"]
    if r.get("casualties", 0) >= 1:
        reasons.append(f"also holds health data: {r['casualties']} casualties")
    if r.get("incidentType") in SAFEGUARDING_INCIDENT_TYPES:
        reasons.append(f"also safeguarding: '{r['incidentType']}' concerns a potentially vulnerable person")
    if r.get("incidentType") in SECURITY_INCIDENT_TYPES:
        label = _raise(label, Classification.SECRET)
        reasons.append(f"SECRET: security-sensitive incident type '{r['incidentType']}'")
    if r.get("incidentType") not in KNOWN_INCIDENT_TYPES:
        label = _raise(label, Classification.CONFIDENTIAL)
        reasons.append("CONFIDENTIAL (provisional): unknown incident type, fail-safe default")
        review.append(f"unknown incidentType '{r.get('incidentType')}'")
    if r.get("priority") == "Critical":
        integrity = Integrity.COMMAND
        reasons.append("COMMAND integrity: Critical incident")
    else:
        integrity = Integrity.OPERATIONAL
        reasons.append("OPERATIONAL integrity: incident record")
    field_integrity = {f: Integrity.UNVERIFIED.name for f in CALLER_FIELDS if f in r}
    if field_integrity:
        reasons.append(f"UNVERIFIED integrity on caller-supplied fields: {', '.join(field_integrity)}")
    return label, integrity, reasons, field_integrity


def classify_intelligence(r: dict, review: list | None = None):
    review = [] if review is None else review
    marking = parse_classification(r["classificationHint"])
    label = marking
    reasons = [f"{label.name}: originator marking (classificationHint)"]
    if r.get("threatLevel") in ("SEVERE", "CRITICAL") and label.value < Classification.SECRET.value:
        label = Classification.SECRET
        reasons.append(f"SECRET: raised from marking because threatLevel is {r['threatLevel']}")
    hits = sorted({m.lower() for m in NATSEC_INDICATORS.findall(r.get("summary", ""))})
    if hits and label.value < Classification.SECRET.value:
        # Content and marking disagree. The originator owns the marking, so it is kept, but the
        # record is queued for a human reviewer rather than trusted blindly.
        reasons.append(f"review: national-security indicators {hits} in summary vs marking {marking.name}")
        review.append(f"content indicators {hits} vs marking {marking.name}")
    if r.get("suspectIdentifier") not in (None, "", "N/A"):
        reasons.append("contains a suspect identifier (personal data under investigation)")
    reasons.append("COMMAND integrity: intelligence report")
    return label, Integrity.COMMAND, reasons, {}


def classify_dispatch(r: dict, review: list | None = None):
    review = [] if review is None else review
    label, reasons = Classification.OFFICIAL, ["OFFICIAL: unit movement record"]
    inc = _raw("incidents").get(r.get("incidentId"))
    integrity = Integrity.OPERATIONAL
    if inc is None:
        label = Classification.CONFIDENTIAL
        reasons.append("CONFIDENTIAL (provisional): linked incident not found, fail-safe default")
        review.append(f"dangling incidentId {r.get('incidentId')}")
    else:
        inc_label, inc_integrity, _, _ = classify_incident(inc)
        if inc_label == Classification.SECRET:
            label = Classification.SECRET
            reasons.append(f"SECRET: inherits from {inc['incidentId']} (security incident); unit movements "
                           f"to it reveal the counter-terrorism response")
        if inc_integrity == Integrity.COMMAND:
            integrity = Integrity.COMMAND
            reasons.append(f"COMMAND integrity: dispatch for Critical incident {inc['incidentId']}")
    if any(u in r.get("unit", "") for u in SECURITY_UNITS) and label.value < Classification.SECRET.value:
        label = Classification.SECRET
        reasons.append(f"SECRET: specialist unit '{r['unit']}'")
    if integrity == Integrity.OPERATIONAL:
        reasons.append("OPERATIONAL integrity: dispatch record")
    return label, integrity, reasons, {}


def classify_audit(r: dict, review: list | None = None):
    review = [] if review is None else review
    res = str(r.get("resource", ""))
    label = BASELINE["audit"]
    reasons = ["CONFIDENTIAL (baseline): records staff identity and activity"]
    ref_label = None
    if res.startswith("INT-") and res in _raw("intelligence"):
        ref_label, _, _, _ = classify_intelligence(_raw("intelligence")[res])
    elif res.startswith("INC-") and res in _raw("incidents"):
        ref_label, _, _, _ = classify_incident(_raw("incidents")[res])
    elif res.startswith(("INT-", "INC-")):
        review.append(f"dangling resource {res}")
    if ref_label is not None and ref_label.value > label.value:
        # An audit line reveals that the referenced record exists and who touched it, so it inherits
        # the record's label. Capped at SECRET: it holds the ID only, not the content, and the
        # SECRET-cleared Auditor must be able to review the whole trail.
        label = Classification.SECRET
        reasons.append(f"SECRET: inherits from {res} ({ref_label.name})")
        if ref_label == Classification.TOP_SECRET:
            reasons.append("capped at SECRET: references a TOP SECRET report by ID only")
            review.append(f"references TOP SECRET report {res}")
    if r.get("action") in HIGH_RISK_AUDIT_ACTIONS:
        reasons.append(f"review: high-risk action '{r['action']}' (insider-abuse indicator)")
        review.append(f"high-risk action '{r['action']}'")
    reasons.append("AUDIT integrity: audit record")
    return label, Integrity.AUDIT, reasons, {}


def classify_responder(r: dict, review: list | None = None):
    review = [] if review is None else review
    label = BASELINE["responders"]
    reasons = ["CONFIDENTIAL (baseline): personnel record with name, station and vetting level"]
    if r.get("role") in COMMAND_ROLES:
        reasons.append(f"identity of a {r['role']}")
    inc_id = r.get("currentAssignment")
    if inc_id:
        inc = _raw("incidents").get(inc_id)
        if inc is None:
            review.append(f"dangling currentAssignment {inc_id}")
        elif classify_incident(inc)[0] == Classification.SECRET:
            label = Classification.SECRET
            reasons.append(f"SECRET: assigned to {inc_id} (security incident); reveals who is deployed on it")
    return label, Integrity.OPERATIONAL, reasons + ["OPERATIONAL integrity: personnel record"], {}


CLASSIFIERS = {
    "incidents": classify_incident,
    "responders": classify_responder,
    "intelligence": classify_intelligence,
    "dispatch": classify_dispatch,
    "audit": classify_audit,
}


def _get_classified_dir():
    """Get classified output directory relative to this module."""
    from pathlib import Path
    return Path(__file__).parent / "classified"


def classify_dataset(name: str, records: list[dict]) -> list[dict]:
    out = []
    for r in records:
        review: list = []
        label, integrity, reasons, field_integrity = CLASSIFIERS[name](r, review)
        rec = dict(r)
        rec["_label"] = label.name
        rec["_integrity"] = integrity.name
        rec["_reasons"] = reasons
        if field_integrity:
            rec["_field_integrity"] = field_integrity
        if review:
            rec["_review"] = review      # ambiguous: provisional label applied, queued for a human
        out.append(rec)
    return out


def write_classified_datasets(output_base=None) -> dict:
    """Part C: classify all records and write classified/<dataset>.json for Part D."""
    output_base = Path(output_base or _get_classified_dir())
    output_base.mkdir(parents=True, exist_ok=True)
    raw = dict(zip(["incidents", "responders", "intelligence", "dispatch", "audit"], load_all()))
    summary = {}
    for name, records in raw.items():
        classified = classify_dataset(name, records)
        (output_base / f"{name}.json").write_text(json.dumps(classified, indent=2, default=str))
        counts = {}
        for rec in classified:
            key = f"{rec['_label']}/{rec['_integrity']}"
            counts[key] = counts.get(key, 0) + 1
        by_label = {c.name: sum(rec["_label"] == c.name for rec in classified)
                    for c in Classification if c != Classification.PUBLIC}
        raised = [next(iter(rec.values())) for rec in classified
                  if Classification[rec["_label"]].value > BASELINE[name].value]
        flagged = [next(iter(rec.values())) for rec in classified if rec.get("_review")]
        summary[name] = {"by_label": by_label, "by_label_integrity": counts,
                         "baseline": BASELINE[name].name, "raised_above_baseline": raised,
                         "review_queue": flagged}
        print(f"[Part C] {name:12s} " + "  ".join(f"{k}={v}" for k, v in by_label.items())
              + f"  raised: {', '.join(raised) or '-'}" + (f"  review: {', '.join(flagged)}" if flagged else ""))
    (output_base / "classification_summary.json").write_text(json.dumps(summary, indent=2))
    return summary


def load_classified(dataset: str) -> list[dict]:
    """Part D: Load pre-classified records from Part C output."""
    path = _get_classified_dir() / f"{dataset}.json"
    if not path.exists():
        raise FileNotFoundError(f"Classified dataset not found: {path}. Run Part C first.")
    return json.loads(path.read_text())


# ---------------------------------------------------------------------------
# Views (Part C3)
#
#   classified store --> OPERATIONAL --> ANALYTICS --> RESEARCH
#                  \--> Guard (threat advisories) --/
#
# Each hop may only drop records, drop fields or generalise values; it never adds source data.
# Downgrading a record's label is done only by a named sanitiser (trusted subject), and every output
# record carries lineage (source dataset, source digest, transform). Every view is signed (Ed25519)
# so a consumer can detect tampering. Intelligence and audit content never leave their domains:
# responders get Guard-issued advisories, never raw reports.
# ---------------------------------------------------------------------------
import hmac
import os
import statistics
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.primitives import serialization

TRANSFORM_VERSION = "views.v2"
VIEW_CEILING = {   # highest label that may appear in each view (after sanitisation)
    "operational": Classification.SECRET,        # per-user access still decided by the Part D engine
    "analytics": Classification.CONFIDENTIAL,
    "research": Classification.OFFICIAL,         # released outside NERP
}
# Fields that must never appear outside the operational view (direct identifiers / sensitive content)
FORBIDDEN_DOWNSTREAM = {"callerName", "callerPhone", "name", "clearanceLevel", "suspectIdentifier",
                        "summary", "reportSource", "actor", "responderId"}
PHONE_RE = re.compile(r"\b07\d{9}\b")

TOWN_COUNTY = {
    "Bristol City Centre": "Bristol", "Bristol Airport": "North Somerset", "Bath": "Somerset",
    "Taunton": "Somerset", "Yeovil": "Somerset", "Weston-super-Mare": "North Somerset",
    "Bridgwater": "Somerset", "Exeter": "Devon", "Plymouth": "Devon", "Torquay": "Devon",
    "Gloucester": "Gloucestershire", "Cheltenham": "Gloucestershire", "Swindon": "Wiltshire",
    "Chippenham": "Wiltshire", "Salisbury": "Wiltshire", "Bournemouth": "Dorset", "Poole": "Dorset",
    "Truro": "Cornwall", "Newquay": "Cornwall", "Cardiff": "Cardiff",
}
COUNTY_REGION = {"Cardiff": "Wales"}             # everything else is South West England
INCIDENT_CATEGORY = {
    "Road Traffic Collision": "Transport", "Medical Emergency": "Medical", "Fire": "Fire & Hazard",
    "Flooding": "Fire & Hazard", "Chemical Spill": "Fire & Hazard", "Building Collapse": "Fire & Hazard",
    "Missing Person": "Public Order & Welfare", "Public Disorder": "Public Order & Welfare",
    "Terrorism Threat": "Security", "Suspicious Package": "Security",
}
THREAT_CATEGORY = {"Counter Terrorism": "terrorism", "Cyber": "cyber", "Police": "serious crime",
                   "Fire": "fire", "Border": "border", "Infrastructure": "infrastructure",
                   "Liaison": "national security"}
ADVISORY_LEVELS = {"HIGH", "SEVERE", "CRITICAL"}     # only actionable threat levels become advisories
K_ANONYMITY = 2


def _canon(obj) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), default=str).encode()


def _digest(rec: dict) -> str:
    return hashlib.sha256(_canon(rec)).hexdigest()[:16]


def _lineage(src_dataset: str, src: dict, transform: str, sanitiser: str | None = None) -> dict:
    out = {"source": src_dataset, "source_digest": _digest(src), "transform": f"{TRANSFORM_VERSION}:{transform}"}
    if sanitiser:
        out["sanitiser"] = sanitiser
    return out


def _region(county: str) -> str:
    return COUNTY_REGION.get(county, "South West England")


def _minutes(dep: str | None, arr: str | None):
    if not dep or not arr:
        return None
    (h1, m1), (h2, m2) = (map(int, dep.split(":")), map(int, arr.split(":")))
    return (h2 * 60 + m2) - (h1 * 60 + m1)


def _time_band(ts: str) -> str:
    h = int(ts[11:13]) if "T" in ts else int(ts.split(":")[0])
    return "06-12" if 6 <= h < 12 else "12-18" if 12 <= h < 18 else "18-24" if h >= 18 else "00-06"


def transform(value, fn):
    """Kept for callers of the old API; new views use the explicit builders below."""
    if value is None:
        return None
    if fn == "date_only":
        return str(value).split("T")[0]
    if fn == "region_only":
        return TOWN_COUNTY.get(value, "Unknown")
    if fn == "unit_type":
        return _unit_type(value)
    return value


def _unit_type(v: str) -> str:
    for key, t in [("Police", "POLICE"), ("Ambulance", "AMBULANCE"), ("Fire", "FIRE"), ("Hazmat", "HAZMAT"),
                   ("Rescue", "RESCUE"), ("Explosives", "EOD"), ("Counter Terror", "CTU")]:
        if key in str(v):
            return t
    return "OTHER"


# -- Hop 1: classified store -> Operational view (emergency responders, dispatchers, commanders) -------
def operational_view(store: dict, guard_key: bytes = b"") -> tuple[dict, dict]:
    guard_key = guard_key or os.urandom(32)
    out, log = {}, {}
    ceiling = VIEW_CEILING["operational"]
    # Incidents and dispatch: full records (responders need caller call-back details and location).
    for ds in ("incidents", "dispatch"):
        recs = [dict(r, _lineage=_lineage(ds, r, "operational.passthrough"))
                for r in store[ds] if Classification[r["_label"]].value <= ceiling.value]
        out[ds] = recs
        log[ds] = {"in": len(store[ds]), "out": len(recs), "fields_removed": [], "fields_transformed": []}
    # Responders: frontline roster only; vetting data removed.
    keep = ["responderId", "name", "role", "station", "currentAssignment"]
    roster = []
    for r in store["responders"]:
        if r["role"] in COMMAND_ROLES:         # command / analyst / auditor identities are not needed
            continue                           # by responders; per-record access is left to Part D
        roster.append({**{f: r.get(f) for f in keep}, "_label": r["_label"], "_integrity": r["_integrity"],
                       "_lineage": _lineage("responders", r, "operational.roster")})
    out["responders"] = roster
    log["responders"] = {"in": len(store["responders"]), "out": len(roster),
                         "fields_removed": ["clearanceLevel"], "fields_transformed": [],
                         "records_withheld": "command, analyst and auditor identities (not operationally needed)"}
    # Intelligence: never raw. The Guard issues advisories for actionable threats from reports up to
    # SECRET; TOP SECRET reports are held for an analyst-authored brief (no automatic downgrade).
    advisories, held = [], []
    for r in store["intelligence"]:
        if r["threatLevel"] not in ADVISORY_LEVELS:
            continue
        if r["_label"] == "TOP_SECRET":
            held.append(r["reportId"])
            continue
        cat = next((c for k, c in THREAT_CATEGORY.items() if k in r["reportSource"]), "other")
        advisories.append({
            "advisoryId": "ADV-" + hmac.new(guard_key, r["reportId"].encode(), hashlib.sha256).hexdigest()[:8],
            "region": r["region"], "threatLevel": r["threatLevel"], "category": cat,
            "guidance": f"Heightened {cat} threat ({r['threatLevel']}) in {r['region']}: follow "
                        f"{'JESIP / CT' if cat in ('terrorism', 'national security') else 'standard'} protocols.",
            "_label": "OFFICIAL", "_integrity": "COMMAND",
            "_reasons": [f"Guard advisory derived from a {r['_label']} report; source, suspect and summary removed"],
            "_lineage": _lineage("intelligence", r, "operational.guard_advisory", sanitiser="Guard"),
        })
    out["threat_advisories"] = advisories
    log["intelligence"] = {"in": len(store["intelligence"]), "out": 0, "advisories_issued": len(advisories),
                           "top_secret_held_for_analyst_brief": held,
                           "fields_removed": ["reportId", "reportSource", "suspectIdentifier", "summary",
                                              "classificationHint"],
                           "fields_transformed": ["reportSource -> category", "threatLevel -> guidance"]}
    out["audit"] = []
    log["audit"] = {"in": len(store["audit"]), "out": 0, "reason": "audit stays in the Oversight domain"}
    return out, log


# -- Hop 2: Operational view -> Analytics view (operational analysis; no direct identifiers) -----------
def analytics_view(op: dict) -> tuple[dict, dict]:
    ceiling = VIEW_CEILING["analytics"]
    log = {}
    inc_out = []
    for r in op["incidents"]:
        if Classification[r["_label"]].value > ceiling.value:
            continue
        rec = {f: r[f] for f in ("incidentId", "timestamp", "location", "incidentType", "casualties",
                                 "priority", "assignedAgency")}
        # Re-label: the baseline reason (caller PII) has gone. Casualty counts and safeguarding
        # incidents keep CONFIDENTIAL (health / vulnerable-person data about the event).
        label = "CONFIDENTIAL" if r["casualties"] or r["incidentType"] in SAFEGUARDING_INCIDENT_TYPES else "OFFICIAL"
        rec.update(_label=label, _integrity=r["_integrity"],
                   _reasons=[f"{label}: downgraded from {r['_label']} by the analytics sanitiser after caller "
                             f"identifiers were removed" if label != r["_label"] else
                             f"{label}: caller identifiers removed; casualty/safeguarding content remains"],
                   _lineage=_lineage("incidents", r, "analytics.strip_pii", sanitiser="Information Governance"))
        inc_out.append(rec)
    log["incidents"] = {"in": len(op["incidents"]), "out": len(inc_out),
                        "records_withheld": len(op["incidents"]) - len(inc_out),
                        "fields_removed": CALLER_FIELDS, "fields_transformed": []}
    labels = {r["incidentId"]: r for r in inc_out}
    disp_out = []
    for r in op["dispatch"]:
        if Classification[r["_label"]].value > ceiling.value or r["incidentId"] not in labels:
            continue
        disp_out.append({
            "dispatchId": r["dispatchId"], "incidentId": r["incidentId"], "unitType": _unit_type(r["unit"]),
            "departureTime": r["departureTime"], "arrivalTime": r["arrivalTime"],
            "responseMinutes": _minutes(r["departureTime"], r["arrivalTime"]), "status": r["status"],
            "_label": "OFFICIAL", "_integrity": r["_integrity"],
            "_lineage": _lineage("dispatch", r, "analytics.unit_type")})
    log["dispatch"] = {"in": len(op["dispatch"]), "out": len(disp_out),
                       "records_withheld": len(op["dispatch"]) - len(disp_out),
                       "fields_removed": ["unit"], "fields_transformed": ["unit -> unitType",
                                                                         "+responseMinutes (derived)"]}
    # Aggregates (counts only) so analysts still see workload, including withheld SECRET incidents.
    by_cat: dict = {}
    for r in op["incidents"]:
        k = INCIDENT_CATEGORY.get(r["incidentType"], "Other")
        by_cat[k] = by_cat.get(k, 0) + 1
    resp = {}
    for d in disp_out:
        if d["responseMinutes"] is not None:
            resp.setdefault(d["unitType"], []).append(d["responseMinutes"])
    roster: dict = {}
    for r in op["responders"]:
        e = roster.setdefault(r["role"], {"total": 0, "assigned": 0})
        e["total"] += 1
        e["assigned"] += r["currentAssignment"] is not None
    aggregates = {
        "_label": "OFFICIAL",
        "incidents_by_category": by_cat,
        "median_response_minutes_by_unit_type": {k: statistics.median(v) for k, v in sorted(resp.items())},
        "responder_utilisation_by_role": roster,
        "threat_advisories_by_level": {lvl: sum(a["threatLevel"] == lvl for a in op["threat_advisories"])
                                       for lvl in sorted(ADVISORY_LEVELS)},
    }
    log["responders"] = {"in": len(op["responders"]), "out": 0, "aggregated": True,
                         "fields_removed": ["responderId", "name", "station", "currentAssignment"]}
    log["intelligence"] = {"in": len(op["threat_advisories"]), "out": 0, "aggregated": True}
    return {"incidents": inc_out, "dispatch": disp_out, "aggregates": aggregates}, log


# -- Hop 3: Analytics view -> Research view (external release; anonymised) ------------------------------
def _k_anonymise(rows: list[dict], qi_levels: list[tuple], k: int, max_suppress: float = 0.2):
    """Pick the finest generalisation level reaching k-anonymity with <= max_suppress suppression."""
    for level in qi_levels:
        name, qi = level
        groups: dict = {}
        for r in rows:
            groups.setdefault(qi(r), []).append(r)
        small = [r for g in groups.values() if len(g) < k for r in g]
        if len(small) <= max_suppress * len(rows):
            kept = [r for r in rows if r not in small]
            min_k = min((len(g) for g in groups.values() if len(g) >= k), default=0)
            return name, qi, kept, small, min_k
    name, qi = qi_levels[-1]
    return name, qi, [], rows, 0


def research_view(an: dict, release_key: bytes) -> tuple[dict, dict]:
    pseud = lambda v: hmac.new(release_key, v.encode(), hashlib.sha256).hexdigest()[:12]
    base = []
    for r in an["incidents"]:
        county = TOWN_COUNTY.get(r["location"], "Unknown")
        base.append({"_src": r, "county": county, "region": _region(county),
                     "category": INCIDENT_CATEGORY.get(r["incidentType"], "Other"),
                     "date": r["timestamp"][:10], "band": _time_band(r["timestamp"])})
    levels = [("county+category+date+time_band", lambda x: (x["county"], x["category"], x["date"], x["band"])),
              ("county+category+date", lambda x: (x["county"], x["category"], x["date"])),
              ("region+category+date+time_band", lambda x: (x["region"], x["category"], x["date"], x["band"])),
              ("region+category+date", lambda x: (x["region"], x["category"], x["date"]))]
    level, qi, kept, suppressed, min_k = _k_anonymise(base, levels, K_ANONYMITY)
    use_county, use_band = level.startswith("county"), "time_band" in level
    casualty_band = lambda c: "0" if c == 0 else "1-2" if c <= 2 else "3+"
    inc_out = []
    for x in kept:
        r = x["_src"]
        rec = {"pid": pseud(r["incidentId"]), "area": x["county"] if use_county else x["region"],
               "category": x["category"], "date": x["date"], "casualties": casualty_band(r["casualties"]),
               "priority": r["priority"], "assignedAgency": r["assignedAgency"]}
        if use_band:
            rec["timeBand"] = x["band"]
        rec.update(_label="OFFICIAL", _integrity="OPERATIONAL",
                   _reasons=[f"OFFICIAL: anonymised ({level}, k>={min_k}); casualties banded; "
                             f"ids pseudonymised with a per-release key"],
                   _lineage=_lineage("incidents", r, "research.k_anonymise", sanitiser="Information Governance"))
        inc_out.append(rec)
    kept_ids = {x["_src"]["incidentId"] for x in kept}
    disp_out = []
    for d in an["dispatch"]:
        if d["incidentId"] not in kept_ids:
            continue
        m = d["responseMinutes"]
        disp_out.append({"pid": pseud(d["dispatchId"]), "incidentPid": pseud(d["incidentId"]),
                         "unitType": d["unitType"],
                         "responseMinutes": None if m is None else ("<=8" if m <= 8 else "9-12" if m <= 12 else ">12"),
                         "status": d["status"], "_label": "OFFICIAL", "_integrity": "OPERATIONAL",
                         "_lineage": _lineage("dispatch", d, "research.pseudonymise",
                                              sanitiser="Information Governance")})
    log = {"incidents": {"in": len(an["incidents"]), "out": len(inc_out), "k": K_ANONYMITY,
                         "achieved_min_class_size": min_k, "generalisation_level": level,
                         "suppressed": [x["_src"]["incidentId"] for x in suppressed],
                         "fields_removed": ["incidentId", "location", "timestamp", "incidentType"],
                         "fields_transformed": ["incidentId -> pid (HMAC, per-release key)",
                                                "location -> area", "incidentType -> category",
                                                "timestamp -> date (+ time band)", "casualties -> band"]},
           "dispatch": {"in": len(an["dispatch"]), "out": len(disp_out),
                        "fields_removed": ["dispatchId", "incidentId", "departureTime", "arrivalTime"],
                        "fields_transformed": ["ids -> pid", "responseMinutes -> band"]}}
    return {"incidents": inc_out, "dispatch": disp_out}, log


# -- Integrity and confidentiality checks ----------------------------------------------------------------
def sign_view(name: str, content: dict, key: ed25519.Ed25519PrivateKey) -> dict:
    body = _canon(content)
    return {"view": name, "transform_version": TRANSFORM_VERSION, "sha256": hashlib.sha256(body).hexdigest(),
            "signature": key.sign(body).hex(),
            "public_key": key.public_key().public_bytes(serialization.Encoding.Raw,
                                                        serialization.PublicFormat.Raw).hex()}


def verify_view(content: dict, manifest: dict) -> bool:
    pub = ed25519.Ed25519PublicKey.from_public_bytes(bytes.fromhex(manifest["public_key"]))
    try:
        pub.verify(bytes.fromhex(manifest["signature"]), _canon(content))
        return True
    except Exception:
        return False


def _records(view: dict):
    for ds, recs in view.items():
        if isinstance(recs, list):
            for r in recs:
                yield ds, r


def check_flows(views: dict, store: dict) -> dict:
    """Machine-checked properties of the information flow (C3 evidence)."""
    names = {r["callerName"] for r in store["incidents"]} | {r["name"] for r in store["responders"]}
    suspects = {r["suspectIdentifier"] for r in store["intelligence"] if r["suspectIdentifier"] != "N/A"}
    digests = {ds: {_digest(r) for r in recs} for ds, recs in store.items()}
    checks = {}
    for vname, view in views.items():
        ceiling = VIEW_CEILING[vname]
        over = [r.get("_lineage", {}).get("source_digest") for _, r in _records(view)
                if Classification[r["_label"]].value > ceiling.value]
        text = json.dumps(view, default=str)
        leaks = []
        if vname != "operational":
            leaks += [f"field:{f}" for _, r in _records(view) for f in r if f in FORBIDDEN_DOWNSTREAM]
            leaks += [f"phone:{m}" for m in PHONE_RE.findall(text)]
            leaks += [f"name:{n}" for n in names if n in text]
        leaks += [f"suspect:{s}" for s in suspects if s in text]
        leaks += [f"raw_audit:{r.get('eventId')}" for ds, r in _records(view) if ds == "audit"]
        # Lineage: every record must trace to a source record; downgrades must name a sanitiser
        orphan = [r.get("_lineage") for _, r in _records(view)
                  if r.get("_lineage", {}).get("source_digest") not in
                  set().union(*digests.values()) | {_digest(x) for _, v in views.items() for _, x in _records(v)}]
        checks[vname] = {"records": sum(1 for _ in _records(view)), "labels_above_ceiling": len(over),
                         "leaks": sorted(set(leaks)), "orphan_records": len(orphan),
                         "pass": not over and not leaks and not orphan}
    return checks


def reidentification_test(research: dict, release_key_destroyed: bool) -> dict:
    """Linkage attack: an outsider enumerates the small incident-ID space (INC-000..INC-999)."""
    pids = {r["pid"] for r in research["incidents"]}
    unsalted = {hashlib.sha256(f"INC-{i:03d}".encode()).hexdigest()[:12]: f"INC-{i:03d}" for i in range(1000)}
    # Old (v1) scheme: unsalted SHA-256 of the ID. How many of today's incidents would it expose?
    v1_hits = sum(hashlib.sha256(f"INC-{i:03d}".encode()).hexdigest()[:12] in unsalted for i in range(1, 21))
    return {"v1_unsalted_sha256_reidentified": f"{v1_hits}/20",
            "v2_hmac_pids_matched_by_enumeration": len(pids & set(unsalted)),
            "release_key_destroyed_after_publication": release_key_destroyed}


def run_part_c():
    """Run Part C: classify and write datasets."""
    write_classified_datasets()


def build_views() -> dict:
    store = {d: load_classified(d) for d in ["incidents", "responders", "intelligence", "dispatch", "audit"]}
    signing_key = ed25519.Ed25519PrivateKey.generate()
    release_key = os.urandom(32)
    op, op_log = operational_view(store)
    an, an_log = analytics_view(op)
    rs, rs_log = research_view(an, release_key)
    release_key = None                                   # destroyed: pids cannot be re-linked to IDs
    views = {"operational": op, "analytics": an, "research": rs}
    manifests = {n: sign_view(n, v, signing_key) for n, v in views.items()}
    tamper = json.loads(json.dumps(rs))
    if tamper["incidents"]:
        tamper["incidents"][0]["casualties"] = "3+"
    return {
        "views": views,
        "flow": {"classified->operational": op_log, "operational->analytics": an_log,
                 "analytics->research": rs_log},
        "manifests": manifests,
        "checks": {
            "flow_properties": check_flows(views, store),
            "signatures_valid": {n: verify_view(v, manifests[n]) for n, v in views.items()},
            "tampered_research_view_detected": not verify_view(tamper, manifests["research"]),
            "reidentification": reidentification_test(rs, release_key is None),
        },
    }


def run_part_d() -> dict:
    """Generate the three views from classified datasets (consumes Part C output)."""
    out = build_views()
    out_path = Path(__file__).parent / "experiments" / "information_views.json"
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(out, indent=2, default=str))
    counts = {v: {ds: len(r) for ds, r in view.items() if isinstance(r, list)} for v, view in out["views"].items()}
    ok = all(c["pass"] for c in out["checks"]["flow_properties"].values())
    print(f"[Part C3] View record counts: {counts}")
    print(f"[Part C3] flow checks pass={ok}, signatures valid={all(out['checks']['signatures_valid'].values())}, "
          f"tampering detected={out['checks']['tampered_research_view_detected']}, "
          f"k-anonymity={out['flow']['analytics->research']['incidents']['generalisation_level']}, "
          f"re-identification={out['checks']['reidentification']}")
    return {"record_counts": counts, "checks": out["checks"],
            "research_generalisation": out["flow"]["analytics->research"]["incidents"]}


if __name__ == "__main__":
    import sys
    if len(sys.argv) > 1 and sys.argv[1] == "part-d":
        run_part_d()
    else:
        run_part_c()
