"""
Multi-Layer Security Policy Engine for NERP
Implements Access Control Matrix, Bell-LaPadula (Confidentiality), Biba (Integrity)
"""
from dataclasses import dataclass, field
from typing import Any
from enum import Enum

from nerp.models import Role, Action, Classification, Integrity, User, load_users


class PolicyDecision(Enum):
    GRANT = "grant"
    DENY = "deny"
    CONFLICT = "conflict"


@dataclass
class PolicyResult:
    decision: PolicyDecision
    acm_result: PolicyDecision
    bell_lapadula_result: PolicyDecision
    biba_result: PolicyDecision
    violated_policies: list[str] = field(default_factory=list)
    reason: str = ""


class AccessControlMatrix:
    """Access Control Matrix defining permissions for each role on each resource type"""

    def __init__(self):
        self.matrix = self._init_matrix()

    def _init_matrix(self) -> dict[Role, dict[str, set[Action]]]:
        # Resource types: incident, intelligence, dispatch, audit, responder, resource_allocation
        # No role may write audit records (system-only, via the Audit Service).
        return {
            Role.PARAMEDIC: {
                "incident": {Action.READ, Action.WRITE},
                "intelligence": set(),
                "dispatch": {Action.READ},
                "audit": set(),
                "responder": {Action.READ},
                "resource_allocation": set(),
            },
            Role.FIRE_OFFICER: {
                "incident": {Action.READ, Action.WRITE},
                "intelligence": {Action.READ},
                "dispatch": {Action.READ},
                "audit": set(),
                "responder": {Action.READ},
                "resource_allocation": set(),
            },
            Role.DISPATCHER: {
                "incident": {Action.READ, Action.CREATE, Action.WRITE},
                "intelligence": {Action.READ},
                "dispatch": {Action.READ, Action.CREATE, Action.WRITE},
                "audit": {Action.READ},
                "responder": {Action.READ, Action.WRITE},
                "resource_allocation": {Action.READ, Action.WRITE},
            },
            Role.POLICE_OFFICER: {
                "incident": {Action.READ, Action.WRITE},
                "intelligence": {Action.READ},
                "dispatch": {Action.READ},
                "audit": set(),
                "responder": {Action.READ},
                "resource_allocation": {Action.READ},
            },
            Role.INTEL_ANALYST: {
                "incident": {Action.READ},
                "intelligence": {Action.READ, Action.CREATE, Action.WRITE, Action.MODIFY_CLASSIFICATION},
                "dispatch": {Action.READ},
                "audit": {Action.READ},
                "responder": {Action.READ},
                "resource_allocation": {Action.READ},
            },
            Role.REGIONAL_CMDR: {
                "incident": {Action.READ, Action.WRITE, Action.MODIFY_CLASSIFICATION, Action.EXPORT},
                "intelligence": {Action.READ, Action.WRITE, Action.MODIFY_CLASSIFICATION, Action.EXPORT},
                "dispatch": {Action.READ, Action.WRITE},
                "audit": {Action.READ, Action.VIEW_AUDIT},
                "responder": {Action.READ, Action.WRITE},
                "resource_allocation": {Action.READ, Action.WRITE, Action.EXPORT},
            },
            Role.NATIONAL_CMDR: {
                "incident": {Action.READ, Action.WRITE, Action.MODIFY_CLASSIFICATION, Action.EXPORT, Action.DELETE},
                "intelligence": {Action.READ, Action.WRITE, Action.MODIFY_CLASSIFICATION, Action.EXPORT, Action.DELETE},
                "dispatch": {Action.READ, Action.WRITE, Action.DELETE},
                "audit": {Action.READ, Action.VIEW_AUDIT, Action.EXPORT},
                "responder": {Action.READ, Action.WRITE, Action.DELETE},
                "resource_allocation": {Action.READ, Action.WRITE, Action.EXPORT, Action.DELETE},
            },
            # CONTRACT: Auditor is read-only; only the system writes audit records.
            Role.AUDITOR: {
                "incident": {Action.READ},
                "intelligence": {Action.READ},
                "dispatch": {Action.READ},
                "audit": {Action.READ, Action.VIEW_AUDIT},
                "responder": {Action.READ},
                "resource_allocation": {Action.READ},
            },
        }

    def check(self, role: Role, resource_type: str, action: Action) -> PolicyDecision:
        allowed = self.matrix.get(role, {}).get(resource_type, set())
        return PolicyDecision.GRANT if action in allowed else PolicyDecision.DENY


class BellLaPadula:
    """Bell-LaPadula Model for Confidentiality: No Read Up, No Write Down"""

    def __init__(self):
        self.levels = {
            Classification.PUBLIC: 0,
            Classification.OFFICIAL: 1,
            Classification.CONFIDENTIAL: 2,
            Classification.SECRET: 3,
            Classification.TOP_SECRET: 4,
        }

    def can_read(self, subject_clearance: Classification, object_classification: Classification) -> PolicyDecision:
        # No Read Up: subject can read object only if subject clearance >= object classification
        if self.levels[subject_clearance] >= self.levels[object_classification]:
            return PolicyDecision.GRANT
        return PolicyDecision.DENY

    def can_write(self, subject_clearance: Classification, object_classification: Classification) -> PolicyDecision:
        # No Write Down: subject can write to object only if subject clearance <= object classification
        if self.levels[subject_clearance] <= self.levels[object_classification]:
            return PolicyDecision.GRANT
        return PolicyDecision.DENY

    def check(self, user: User, resource_classification: Classification, action: Action) -> PolicyDecision:
        if action in (Action.READ, Action.VIEW_AUDIT):
            return self.can_read(user.clearance, resource_classification)
        elif action in (Action.WRITE, Action.CREATE, Action.DELETE, Action.MODIFY_CLASSIFICATION, Action.EXPORT):
            return self.can_write(user.clearance, resource_classification)
        return PolicyDecision.DENY


class Biba:
    """Biba Model for Integrity: No Read Down, No Write Up"""

    def __init__(self):
        self.levels = {
            Integrity.UNVERIFIED: 0,
            Integrity.OPERATIONAL: 1,
            Integrity.COMMAND: 2,
            Integrity.AUDIT: 3,
        }

    def can_read(self, subject_integrity: Integrity, object_integrity: Integrity) -> PolicyDecision:
        # No Read Down: subject can read object only if subject integrity <= object integrity
        if self.levels[subject_integrity] <= self.levels[object_integrity]:
            return PolicyDecision.GRANT
        return PolicyDecision.DENY

    def can_write(self, subject_integrity: Integrity, object_integrity: Integrity) -> PolicyDecision:
        # No Write Up: subject can write to object only if subject integrity >= object integrity
        if self.levels[subject_integrity] >= self.levels[object_integrity]:
            return PolicyDecision.GRANT
        return PolicyDecision.DENY

    def check(self, user: User, resource_integrity: Integrity, action: Action) -> PolicyDecision:
        if action in (Action.READ, Action.VIEW_AUDIT):
            return self.can_read(user.integrity, resource_integrity)
        elif action in (Action.WRITE, Action.CREATE, Action.DELETE, Action.MODIFY_CLASSIFICATION, Action.EXPORT):
            return self.can_write(user.integrity, resource_integrity)
        return PolicyDecision.DENY


class PolicyEngine:
    """Integrated Policy Engine combining ACM, Bell-LaPadula, and Biba"""

    def __init__(self):
        self.acm = AccessControlMatrix()
        self.bell_lapadula = BellLaPadula()
        self.biba = Biba()

    def evaluate(self, user: User, resource_type: str, action: Action,
                 resource_classification: Classification,
                 resource_integrity: Integrity) -> PolicyResult:

        acm_result = self.acm.check(user.role, resource_type, action)
        bl_result = self.bell_lapadula.check(user, resource_classification, action)
        biba_result = self.biba.check(user, resource_integrity, action)

        violated = []
        if acm_result == PolicyDecision.DENY:
            violated.append("ACM")
        if bl_result == PolicyDecision.DENY:
            violated.append("Bell-LaPadula")
        if biba_result == PolicyDecision.DENY:
            violated.append("Biba")

        # Final decision: deny if ANY policy denies (conservative)
        if violated:
            decision = PolicyDecision.DENY
            reason = f"Denied by: {', '.join(violated)}"
        else:
            decision = PolicyDecision.GRANT
            reason = "All policies permit"

        return PolicyResult(
            decision=decision,
            acm_result=acm_result,
            bell_lapadula_result=bl_result,
            biba_result=biba_result,
            violated_policies=violated,
            reason=reason
        )

    # -- Part C -> D handoff ------------------------------------------------
    def evaluate_record(self, user: User, dataset: str, record: dict, action: Action) -> PolicyResult:
        """Evaluate access to a classified record. Reads only _label / _integrity (CONTRACT)."""
        return self.evaluate(user, DATASET_RESOURCE[dataset], action,
                             Classification[record["_label"]], Integrity[record["_integrity"]])

    def demonstrate_conflicts(self) -> list[dict]:
        """Task D4 scenarios, built from real users (responders.json) and Part C records."""
        users = {u.role: u for u in load_users()}
        records = load_records()

        def pick(dataset, pred):
            return next(r for r in records[dataset] if pred(r))

        def rid(r):
            return r.get("incidentId") or r.get("reportId") or r.get("dispatchId") or r.get("eventId")

        cases = [
            ("ACM permits but Bell-LaPadula prevents", Role.POLICE_OFFICER, "intelligence", Action.READ,
             pick("intelligence", lambda r: r["_label"] == "TOP_SECRET"),
             "Confidentiality: No Read Up (SECRET subject, TOP SECRET object)"),
            ("Bell-LaPadula permits but Biba prevents", Role.PARAMEDIC, "incidents", Action.WRITE,
             pick("incidents", lambda r: r["_integrity"] == "COMMAND"),
             "Integrity: No Write Up (OPERATIONAL subject, COMMAND Critical incident)"),
            ("All security controls permit", Role.REGIONAL_CMDR, "intelligence", Action.READ,
             pick("intelligence", lambda r: r["_label"] == "SECRET"),
             "Operational effectiveness: cleared commander reads SECRET intelligence"),
            ("Both MAC models permit but ACM prevents", Role.PARAMEDIC, "intelligence", Action.READ,
             pick("intelligence", lambda r: r["_label"] == "OFFICIAL"),
             "Need-to-know: paramedics have no intelligence role permission"),
            ("Conflict: strict Biba blocks a legitimate read", Role.REGIONAL_CMDR, "incidents", Action.READ,
             pick("incidents", lambda r: r["_integrity"] == "OPERATIONAL"),
             "Biba No Read Down stops a COMMAND subject reading OPERATIONAL incidents"),
            ("Conflict: analyst cannot write intelligence", Role.INTEL_ANALYST, "intelligence", Action.WRITE,
             pick("intelligence", lambda r: r["_label"] == "TOP_SECRET"),
             "Biba No Write Up: OPERATIONAL analyst vs COMMAND intelligence"),
        ]
        scenarios = []
        for title, role, dataset, action, rec, prop in cases:
            user = users[role]
            res = self.evaluate_record(user, dataset, rec, action)
            scenarios.append({
                "scenario": title,
                "user": f"{user.name} ({role.value}, {user.clearance.name}, {user.integrity.name})",
                "action": f"{action.value} {dataset}",
                "resource": f"{rid(rec)} ({rec['_label']}, {rec['_integrity']})",
                "acm": res.acm_result.value,
                "bell_lapadula": res.bell_lapadula_result.value,
                "biba": res.biba_result.value,
                "final": res.decision.value,
                "property_protected": prop,
            })
        return scenarios

    def outcome_matrix(self) -> dict:
        """Grant counts for every role x dataset x action over all classified records."""
        users = {}
        for u in load_users():
            users.setdefault(u.role, u)  # one representative per role
        records = load_records()
        out = {}
        for role, user in users.items():
            out[role.value] = {}
            for dataset, recs in records.items():
                out[role.value][dataset] = {
                    a.value: sum(self.evaluate_record(user, dataset, r, a).decision == PolicyDecision.GRANT
                                 for r in recs)
                    for a in (Action.READ, Action.WRITE)
                } | {"total": len(recs)}
        return out


DATASET_RESOURCE = {
    "incidents": "incident",
    "intelligence": "intelligence",
    "dispatch": "dispatch",
    "audit": "audit",
    "responders": "responder",
}

# CONTRACT: "Until C is ready, D hard-codes them for 5 records."
FALLBACK_RECORDS = {
    "incidents": [{"incidentId": "INC-001", "_label": "SECRET", "_integrity": "OPERATIONAL", "_reasons": ["fallback"]},
                  {"incidentId": "INC-004", "_label": "CONFIDENTIAL", "_integrity": "COMMAND", "_reasons": ["fallback"]}],
    "intelligence": [{"reportId": "INT-001", "_label": "SECRET", "_integrity": "COMMAND", "_reasons": ["fallback"]},
                     {"reportId": "INT-002", "_label": "TOP_SECRET", "_integrity": "COMMAND", "_reasons": ["fallback"]},
                     {"reportId": "INT-005", "_label": "OFFICIAL", "_integrity": "COMMAND", "_reasons": ["fallback"]}],
    "dispatch": [], "audit": [], "responders": [],
}


def load_records() -> dict:
    """Load Part C output; fall back to the 5 hard-coded records only if Part C has not run."""
    from nerp.information_flow import load_classified
    try:
        return {d: load_classified(d) for d in DATASET_RESOURCE}
    except FileNotFoundError:
        print("[WARN] Part C output missing - using 5 hard-coded fallback records (CONTRACT)")
        return FALLBACK_RECORDS


def save_policy_evidence(output_dir=None) -> dict:
    import json
    from pathlib import Path
    out = Path(output_dir or Path(__file__).parent / "experiments")
    out.mkdir(parents=True, exist_ok=True)
    engine = PolicyEngine()
    data = {"scenarios": engine.demonstrate_conflicts(), "outcome_matrix": engine.outcome_matrix()}
    (out / "policy_conflicts.json").write_text(json.dumps(data, indent=2))
    return data


if __name__ == "__main__":
    data = save_policy_evidence()
    print("POLICY CONFLICT DEMONSTRATION (Task D4)")
    print("=" * 60)
    for s in data["scenarios"]:
        print(f"\n{s['scenario']}")
        print(f"  User: {s['user']}")
        print(f"  Action: {s['action']} on {s['resource']}")
        print(f"  ACM: {s['acm']}, Bell-LaPadula: {s['bell_lapadula']}, Biba: {s['biba']}  ->  FINAL: {s['final']}")
    print("\nOUTCOME MATRIX (records granted / total)")
    for role, ds in data["outcome_matrix"].items():
        print(f"  {role:15s} " + "  ".join(f"{d}: R{v['read']}/W{v['write']} of {v['total']}" for d, v in ds.items()))
    print("\n[SAVED] experiments/policy_conflicts.json")
