#!/usr/bin/env python3
"""
Security Governance (Part E) - Minimal working version
Loads datasets, runs impact assessments and governance decisions, outputs JSON.
"""
from dataclasses import dataclass, asdict
from enum import Enum
import json
from pathlib import Path

class ImpactLevel(Enum):
    LOW = "low"; MEDIUM = "medium"; HIGH = "high"; CRITICAL = "critical"

class Priority(Enum):
    CONFIDENTIALITY = "confidentiality"
    INTEGRITY = "integrity"
    AVAILABILITY = "availability"
    OPERATIONAL = "operational_effectiveness"

@dataclass
class ImpactAssessment:
    scenario: str
    security_properties: list[str]
    components: list[str]
    consensus_assumptions: list[str]
    classification_impact: str
    policy_impact: str
    retention_impact: str
    severity: ImpactLevel

@dataclass
class GovernanceDecision:
    scenario: str
    action: str
    prioritized: list[Priority]
    sacrificed: list[Priority]
    confidentiality: str
    integrity: str
    availability: str
    operational: str
    residual_risk: str

IMPACT_ASSESSMENTS = [
    ImpactAssessment("Research org requests unrestricted intelligence access",
        ["Confidentiality","Integrity"], ["Intelligence","Policy","Classification","InfoFlow"],
        ["BFT validator authenticity","Fixed validator membership"],
        "TOP SECRET exposed", "BLP/Biba violated", "Retention conflict", ImpactLevel.CRITICAL),
    ImpactAssessment("Responders request classified access",
        ["Confidentiality","Operational"], ["Intelligence","Policy","ACM","InfoFlow"],
        ["BFT quorum certificates","Fixed validator membership"],
        "Classification boundaries broken", "ACM/BLP changes needed", "Longer audit retention", ImpactLevel.HIGH),
    ImpactAssessment("Regional datacenter permanently unavailable",
        ["Availability","Integrity"], ["IncidentDB","Dispatch","Consensus","Replication"],
        ["Raft majority","Paxos majority","BFT 3f+1"],
        "Failover may expose data", "Policy must replicate", "Signed audit log must survive", ImpactLevel.HIGH),
    ImpactAssessment("Validator credentials compromised",
        ["Integrity","Confidentiality","Non-repudiation"], ["AuditLog","BFT","Hardening","Keys"],
        ["Epoch key rotation","Equivocation-proof revocation","Quorum certificates"],
        "SECRET audit at risk", "Biba/BLP violated", "20yr retention undermined", ImpactLevel.CRITICAL),
    ImpactAssessment("New regulation: 20yr retention for all records",
        ["Confidentiality","Integrity","Availability"], ["All Datastores","Retention","Governance","Archive","Audit"],
        ["Long-term keys","20yr storage integrity","Format readability"],
        "Exposure risk increases", "Policy versioning needed", "Unified 20yr minimum", ImpactLevel.HIGH),
]

GOVERNANCE_DECISIONS = [
    GovernanceDecision("Research org requests unrestricted intelligence access",
        "Deny unrestricted. Provide sanitized Research View via InfoFlow (PII removed, summaries only). Require data sharing agreement with audit trail.",
        [Priority.CONFIDENTIALITY, Priority.INTEGRITY], [Priority.OPERATIONAL],
        "Preserved: TOP SECRET stays in the Intelligence domain",
        "Preserved: Research view read-only, verified transform",
        "Reduced: Delayed, limited access",
        "Minimal: Operational views unchanged",
        "Re-identification risk; mitigated by k-anonymity/differential privacy"),
    GovernanceDecision("Responders request classified access",
        "Deny direct access. Intelligence Analysts produce sanitized Operational Briefs (CONFIDENTIAL). Responders access briefs, not raw intel.",
        [Priority.CONFIDENTIALITY, Priority.OPERATIONAL], [Priority.AVAILABILITY],
        "Preserved: Raw intel stays in the Intelligence domain",
        "Preserved: Briefs created by authorized analysts under Biba",
        "Reduced: Wait for analyst briefs",
        "Balanced: Actionable intel without violation",
        "Brief production delay; mitigated by pre-positioned analysts/templates"),
    GovernanceDecision("Regional datacenter permanently unavailable",
        "Activate cross-region failover. Reconfigure quorums. Rebuild when restored. Audit failover.",
        [Priority.AVAILABILITY, Priority.INTEGRITY], [Priority.CONFIDENTIALITY],
        "Reduced: Temp clearance differences; mitigated by policy replication",
        "Preserved: Raft/Paxos/BFT state survives; quorum certs verify",
        "Preserved: the two surviving regions keep a majority and continue",
        "Minor: Latency to new primary",
        "Split-brain during detection; mitigated by Raft lease/BFT partition tolerance"),
    GovernanceDecision("Validator credentials compromised",
        "Revoke via Hardening. Activate key rotation. Rebuild audit from last quorum cert. Forensic analysis. Mandate HSM keys.",
        [Priority.INTEGRITY, Priority.CONFIDENTIALITY], [Priority.AVAILABILITY],
        "Preserved: Key rotation limits exposure; separate encryption keys",
        "Restored: Pre-compromise certs valid; post-compromise flagged",
        "Reduced: Audit degraded hours; ops unaffected",
        "Minimal: Separate validators for ops consensus",
        "Undetected forgeries between compromise/detection; mitigated by hash-chain comparison across 2f+1 validators"),
    GovernanceDecision("New regulation: 20yr retention",
        "Unified 20yr minimum tier. Signed, tamper-evident audit log. Policy versioning with timestamps. Plan post-quantum agility. Budget 20yr storage/keys.",
        [Priority.INTEGRITY, Priority.CONFIDENTIALITY], [Priority.AVAILABILITY, Priority.OPERATIONAL],
        "Preserved: Classification enforced 20yrs; key rotation extends",
        "Enhanced: hash-chain heads published, format migration",
        "Reduced: Storage costs up; archive latency higher",
        "Increased: Compliance burden; evaluate 20yr-old policies",
        "Crypto obsolescence; mitigated by agility framework/migration plan"),
]

ASSURANCE_STATEMENT = """NERP Security Assurance Statement

Most Significant Residual Risks:
1. Cryptographic Agility: 20yr confidentiality depends on unbroken algorithms; post-quantum plan untested.
2. Insider Threat in the Intelligence domain: BFT/BLP mitigate but can't eliminate cleared personnel exfiltration.
3. Consensus Liveness Under Partition: Raft/Paxos need majority; extended partition loses availability.
4. Key Management at Scale: HSM keys for every validator; single HSM failure could cascade.
5. Policy Conflict Resolution: Conservative deny-by-default may impede emergency ops.

Critical Assumptions:
- <1/3 BFT validators Byzantine (fixed, governed membership; see bft-sybil)
- Raft/Paxos majorities connected (multi-region)
- HSMs correctly generate/protect keys
- Classification labels accurate (auto engine + human review)
- Policy engine correctly implements ACM/BLP/Biba (tested via outcome matrix; not formally verified)
- Audit Service signs events correctly (corruption before signing is replicated; see bft-audit-corruption)

Most Important Controls:
1. Consensus Hardening: epoch keys, equivocation-proof revocation and quorum certificates (bft-key-compromise).
2. Multi-Layer Policy Engine: ACM+BLP+Biba defence-in-depth.
3. Information Flow Engine: Classification boundaries at data level.
4. Cross-Region Consensus: Geographic diversity survives datacenter loss.
5. Continuous Experimentation: Attack sims validate assumptions regularly.

Recommendation: CONDITIONED deployment - pilot with live shadowing, independent pentest, formal verification of BLP/Biba, 24/7 SOC, annual assumption re-evaluation.
NERP is not perfectly secure but provides reasoned basis for trust via defence-in-depth, protocol diversity, crypto hardening, and evidence-based assurance.
"""

def save_governance(output_path=None, retention_20y: dict | None = None):
    output_path = output_path or Path(__file__).parent / "experiments" / "governance.json"
    Path(output_path).parent.mkdir(parents=True, exist_ok=True)
    data = {
        "impact_assessments": [asdict(ia) for ia in IMPACT_ASSESSMENTS],
        "governance_decisions": [asdict(gd) for gd in GOVERNANCE_DECISIONS],
        "assurance_statement": ASSURANCE_STATEMENT
    }
    if retention_20y:   # E1 scenario 5, measured by nerp/retention.py rather than asserted
        data["measured_20y_retention_impact"] = retention_20y
    # Convert enums to values
    for ia in data["impact_assessments"]:
        ia["severity"] = ia["severity"].value
    for gd in data["governance_decisions"]:
        gd["prioritized"] = [p.value for p in gd["prioritized"]]
        gd["sacrificed"] = [p.value for p in gd["sacrificed"]]
    with open(output_path, 'w') as f:
        json.dump(data, f, indent=2)
    print(f"[SAVED] Governance to {output_path}")

if __name__ == "__main__":
    save_governance()