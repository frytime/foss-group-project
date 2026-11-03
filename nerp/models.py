from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Optional
import json


class Classification(Enum):
    PUBLIC = 0
    OFFICIAL = 1
    CONFIDENTIAL = 2
    SECRET = 3
    TOP_SECRET = 4


class Integrity(Enum):
    UNVERIFIED = 0
    OPERATIONAL = 1
    COMMAND = 2
    AUDIT = 3


class Role(Enum):
    PARAMEDIC = "paramedic"
    FIRE_OFFICER = "fire_officer"
    DISPATCHER = "dispatcher"
    POLICE_OFFICER = "police_officer"
    INTEL_ANALYST = "intel_analyst"
    REGIONAL_CMDR = "regional_cmdr"
    NATIONAL_CMDR = "national_cmdr"
    AUDITOR = "auditor"


class Action(Enum):
    READ = "read"
    WRITE = "write"
    CREATE = "create"
    DELETE = "delete"
    MODIFY_CLASSIFICATION = "modify_classification"
    EXPORT = "export"
    VIEW_AUDIT = "view_audit"


class SecurityDomain(Enum):
    OPERATIONAL = "operational"
    OVERSIGHT = "oversight"
    INTELLIGENCE = "intelligence"


class TrustBoundary(Enum):
    """A trust boundary is the line between two zones of different trust; the value names both sides."""
    USER = "TB1 Users/Internet -> API Gateway"
    OPERATIONAL = "TB2 Entry services -> Operational domain"
    INTELLIGENCE = "TB3 Operational domain -> Intelligence domain (Guard)"
    OVERSIGHT = "TB4 Operational/Intelligence domains -> Oversight domain"
    RESEARCHER = "TB5 NERP -> External research partners"


@dataclass
class User:
    id: str
    name: str
    role: Role
    clearance: Classification
    integrity: Integrity
    location: str = ""


@dataclass
class Incident:
    id: str
    timestamp: datetime
    caller_name: str
    caller_phone: str
    location: str
    incident_type: str
    casualties: int
    priority: str
    assigned_agency: str
    classification: Classification = Classification.OFFICIAL
    integrity: Integrity = Integrity.OPERATIONAL
    _label: Optional[str] = None
    _integrity: Optional[str] = None
    _reasons: list = field(default_factory=list)


@dataclass
class Intelligence:
    id: str
    source: str
    threat_level: str
    region: str
    suspect_id: str
    summary: str
    classification: Classification
    integrity: Integrity = Integrity.COMMAND
    _label: Optional[str] = None
    _integrity: Optional[str] = None
    _reasons: list = field(default_factory=list)


@dataclass
class Dispatch:
    id: str
    incident_id: str
    unit: str
    departure_time: str
    arrival_time: Optional[str]
    status: str
    classification: Classification = Classification.OFFICIAL
    integrity: Integrity = Integrity.OPERATIONAL
    _label: Optional[str] = None
    _integrity: Optional[str] = None
    _reasons: list = field(default_factory=list)


@dataclass
class Audit:
    id: str
    actor: str
    action: str
    resource: str
    timestamp: datetime
    classification: Classification = Classification.SECRET
    integrity: Integrity = Integrity.AUDIT
    _label: Optional[str] = None
    _integrity: Optional[str] = None
    _reasons: list = field(default_factory=list)


def load_json(path: str):
    with open(path) as f:
        return json.load(f)


def _get_data_dir():
    """Get data directory - tries multiple locations for portability."""
    from pathlib import Path
    import os
    
    # 1. Relative to module (standard layout)
    module_data = Path(__file__).parent.parent / "data"
    if module_data.exists():
        return module_data
    
    # 2. Relative to cwd (when running from nerp/ dir)
    cwd_data = Path.cwd() / "data"
    if cwd_data.exists():
        return cwd_data
    
    # 3. Parent of cwd (when running from project root)
    parent_data = Path.cwd().parent / "data"
    if parent_data.exists():
        return parent_data
    
    # 4. Environment variable override
    if "NERP_DATA_DIR" in os.environ:
        env_data = Path(os.environ["NERP_DATA_DIR"])
        if env_data.exists():
            return env_data
    
    # Default to module-relative (will error clearly if not found)
    return module_data


DATASET_FILES = {
    "incidents": "incidents.json",
    "responders": "responders.json",
    "intelligence": "intelligence.json",
    "dispatch": "dispatch.json",
    "audit": "audit.json",
}


def load_all():
    """Load the five NERP datasets. Fails loudly if any are missing (no synthetic fallback)."""
    base = _get_data_dir()
    missing = [f for f in DATASET_FILES.values() if not (base / f).exists()]
    if missing:
        raise FileNotFoundError(f"Missing datasets in {base}: {missing}")
    return [load_json(str(base / f)) for f in DATASET_FILES.values()]


def load_dataset(path: str):
    from pathlib import Path
    p = Path(path)
    if not p.exists():
        p = _get_data_dir() / p.name
    return load_json(str(p))


def parse_incidents(data: list) -> list[dict]:
    return data


def parse_intelligence(data: list) -> list[dict]:
    return data


def parse_dispatches(data: list) -> list[dict]:
    return data


def parse_audit(data: list) -> list[dict]:
    return data


def parse_users(data: list) -> list[dict]:
    return data


# ---------------------------------------------------------------------------
# CONTRACT: role profiles (clearance, integrity)
# ---------------------------------------------------------------------------

def parse_classification(label: str) -> Classification:
    """Accepts 'TOP SECRET', 'TOP_SECRET', 'top secret' etc."""
    return Classification[str(label).strip().upper().replace(" ", "_")]


ROLE_NAMES = {
    "Paramedic": Role.PARAMEDIC,
    "Fire Officer": Role.FIRE_OFFICER,
    "Dispatcher": Role.DISPATCHER,
    "Police Officer": Role.POLICE_OFFICER,
    "Intelligence Analyst": Role.INTEL_ANALYST,
    "Regional Commander": Role.REGIONAL_CMDR,
    "National Commander": Role.NATIONAL_CMDR,
    "Auditor": Role.AUDITOR,
}

# clearance None = "per record" (taken from responders.json clearanceLevel)
ROLE_PROFILES = {
    Role.PARAMEDIC:      (Classification.OFFICIAL,   Integrity.OPERATIONAL),
    Role.FIRE_OFFICER:   (Classification.OFFICIAL,   Integrity.OPERATIONAL),
    Role.DISPATCHER:     (Classification.OFFICIAL,   Integrity.OPERATIONAL),
    Role.POLICE_OFFICER: (Classification.SECRET,     Integrity.OPERATIONAL),
    Role.INTEL_ANALYST:  (None,                      Integrity.OPERATIONAL),
    Role.REGIONAL_CMDR:  (Classification.TOP_SECRET, Integrity.COMMAND),
    Role.NATIONAL_CMDR:  (Classification.TOP_SECRET, Integrity.COMMAND),
    Role.AUDITOR:        (Classification.SECRET,     Integrity.AUDIT),
}


def user_from_responder(rec: dict) -> User:
    role = ROLE_NAMES[rec["role"]]
    clearance, integrity = ROLE_PROFILES[role]
    if clearance is None:  # Intel Analyst: per record, SECRET or TOP SECRET
        clearance = parse_classification(rec["clearanceLevel"])
        if clearance not in (Classification.SECRET, Classification.TOP_SECRET):
            raise ValueError(f"Intel Analyst {rec['responderId']} must be SECRET or TOP SECRET")
    return User(rec["responderId"], rec["name"], role, clearance, integrity, rec.get("station", ""))


def load_users() -> list[User]:
    """Users from responders.json plus the contract's added Dispatcher."""
    responders = load_json(str(_get_data_dir() / "responders.json"))
    users = [user_from_responder(r) for r in responders]
    c, i = ROLE_PROFILES[Role.DISPATCHER]
    users.append(User("DSP-001", "Control Room Dispatcher", Role.DISPATCHER, c, i, "Control Room"))
    return users
