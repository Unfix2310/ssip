"""
Regulatory Catalog: canonical entities for RBI/DPSS compliance controls.

Expanded from RBI/2023-24/107 — all 32 sections covered.

Fixes applied vs previous version:
  - No duplicate aliases across keys (last-write-wins issue resolved)
  - cyber_incidents retained as separate resource key
  - report_incident and report_incident_to_rbi merged into report_incident
  - sensitive_data alias retained under crypto_algorithms
  - implement_access_controls and implement_least_privilege aliases separated
  - _build_alias_table now raises ValueError on collision at import time
"""

from __future__ import annotations
import logging

logger = logging.getLogger(__name__)

# ── Subject catalog ───────────────────────────────────────────────────────────
# Rule: each alias belongs to exactly ONE key.
# "banks" -> bank, "psos" -> payment_system_operator, "nbfcs" -> nbfc

SUBJECTS: dict[str, list[str]] = {
    "regulated_entity": [
        "regulated entities",
        "regulated entity",
        "res",
        "financial institutions",
        "all entities",
        "entities",
        "small finance banks",
        "payments banks",
        "credit information companies",
        "all india financial institutions",
        "aifis",
    ],
    "payment_system_operator": [
        "payment system operators",
        "payment system operator",
        "pso",
        "psos",
        "non-bank payment system operator",
        "non-bank pso",
        "payment operators",
        "authorised non-bank psos",
    ],
    "bank": [
        "bank",
        "banks",
        "scheduled commercial banks",
        "scbs",
        "commercial banks",
        "foreign banks",
    ],
    "nbfc": [
        "nbfc",
        "nbfcs",
        "non-banking financial company",
        "non-banking financial companies",
        "top layer nbfc",
        "upper layer nbfc",
        "middle layer nbfc",
    ],
    "board_of_directors": [
        "board of directors",
        "board",
        "board level committee",
        "audit committee of the board",
        "acb",
        "risk management committee of the board",
        "rmcb",
        "it strategy committee",
        "itsc",
    ],
    "senior_management": [
        "senior management",
        "it steering committee",
        "head of it function",
        "cto",
        "cio",
        "chief technology officer",
        "chief information officer",
        "chief information security officer",
        "ciso",
    ],
}

# ── Action catalog ────────────────────────────────────────────────────────────
# Rule: each alias belongs to exactly ONE key.

ACTIONS: dict[str, list[str]] = {

    # Chapter II: IT Governance
    "establish_it_governance_framework": [
        "establish it governance framework",
        "put in place it governance framework",
        "implement it governance framework",
        "it governance framework shall be put in place",
        "robust it governance framework",
        "it governance",
    ],
    "approve_it_strategies_and_policies": [
        "approve it and information security strategies and policies",
        "approve strategies and policies",
        "board approval of it strategy",
        "strategies and policies shall be approved",
        "reviewed at least annually by the board",
        "annual review of it strategy",
    ],
    "establish_it_strategy_committee": [
        "establish board-level it strategy committee",
        "establish itsc",
        "constitute itsc",
        "it strategy committee of the board",
        "board-level it strategy committee",
        "itsc shall be established",
    ],
    "conduct_itsc_meeting": [
        "itsc shall meet",
        "it strategy committee meeting",
        "quarterly itsc meeting",
        "meet at least on a quarterly basis",
    ],
    "establish_it_steering_committee": [
        "establish it steering committee",
        "it steering committee with representation",
        "it steering committee at senior management level",
        "senior management committee for it",
        "senior management level committee",
        "it steering committee shall meet",
        "quarterly steering committee meeting",
        "steering committee with cross-functional representation",
        "constitute it steering committee",
        "it steering committee shall be constituted",
    ],
    "appoint_head_of_it": [
        "appoint head of it function",
        "appoint cto",
        "appoint cio",
        "head of it function shall be appointed",
        "appoint sufficiently senior it official",
        "head of it",
    ],

    # Chapter III: IT Infrastructure & Services Management
    "establish_it_service_management": [
        "put in place it service management framework",
        "establish it service management framework",
        "it service management",
        "service level management",
        "slm process",
        "robust it service management",
    ],
    "manage_third_party_arrangements": [
        "put in place vendor risk assessment process and controls",
        "manage third party arrangements",
        "vendor risk assessment",
        "third-party risk management",
        "manage supply chain risks",
        "third party arrangements",
        "vendor risk",
    ],
    "conduct_capacity_assessment": [
        "conduct capacity assessment",
        "assess capacity requirement",
        "it capacity planning",
        "capacity management",
        "proactively assess capacity",
        "capacity requirement assessment",
    ],
    "follow_project_management_approach": [
        "follow project management approach",
        "consistent project management approach",
        "formally defined project management",
        "enterprise architecture planning",
        "it project management",
    ],
    "implement_patch_management": [
        "implement patch management",
        "put in place patch management policy",
        "change and patch management",
        "documented patch management policy",
        "patch management procedures",
        "change management policy",
    ],
    "apply_critical_patches": [
        "apply critical patches",
        "critical patches must be applied",
        "apply patches immediately",
        "install critical patches",
        "patches shall be applied",
        "critical patch deployment",
    ],
    "implement_data_migration_controls": [
        "implement data migration controls",
        "documented data migration policy",
        "data migration policy",
        "systematic process for data migration",
        "data migration",
    ],
    "enforce_audit_trails": [
        "enforce audit trails",
        "provide audit trails",
        "provide comprehensive audit trails",
        "audit and system logging capability",
        "implement audit trails",
        "audit trails shall be maintained",
        "monitor audit trails",
        "monitoring of audit trails",
        "comprehensive audit trails",
    ],
    "preserve_audit_logs": [
        "preserve audit logs",
        "maintain audit logs",
        "retain audit logs",
        "audit logs shall be preserved",
        "maintain and preserve audit logs",
        "audit logs preserved for minimum period",
    ],
    "enforce_crypto_standards": [
        "enforce cryptographic standards",
        "enforce cryptographic controls",
        "implement cryptographic controls",
        "use approved cryptographic algorithms",
        "use non-deprecated crypto",
        "non-deprecated cryptographic algorithms",
        "approved cryptographic algorithms",
        "key length and algorithms shall be strong",
        "cipher suites shall be strong",
        "adopt internationally accepted cryptographic standards",
    ],
    "implement_straight_through_processing": [
        "implement straight through processing",
        "ensure straight through processing",
        "no manual intervention in data transfer",
        "straight through processing",
        "prevent unauthorised modification of data",
        "securely automated data transfer",
    ],
    "implement_physical_controls": [
        "implement physical and environmental controls",
        "physical and environmental controls",
        "physical controls in data centre",
        "dc and dr physical controls",
        "e-surveillance mechanism",
        "physical security controls",
    ],
    # implement_access_controls: owns need-based access and documented procedures
    "implement_access_controls": [
        "implement access controls",
        "implement need-based access control",
        "access shall be allowed only where valid business need exists",
        "documented access control standards",
        "administer need-based access",
        "access control policy",
        "need-based access to an information system",
        "need-based access",
    ],
    # implement_least_privilege: owns least-privilege principle
    "implement_least_privilege": [
        "implement least privilege",
        "follow the principle of least privilege",
        "least privilege access",
        "need-to-know basis",
        "principle of least privilege",
        "least privilege",
    ],
    "enforce_mfa": [
        "enforce multi-factor authentication",
        "enforce mfa",
        "multi-factor authentication must be enforced",
        "mfa must be enforced",
        "implement mfa",
        "adopt multi-factor authentication",
        "mfa for privileged users",
        "multi-factor authentication for privileged users",
    ],
    "implement_teleworking_controls": [
        "implement teleworking controls",
        "controls on teleworking",
        "remote access security",
        "secure remote access",
        "teleworking security",
        "multi-factor authentication for enterprise access",
    ],
    "define_it_metrics": [
        "define suitable metrics",
        "define it metrics",
        "implement scorecard for it performance",
        "rpo and rto metrics",
        "recovery point objective",
        "recovery time objective",
        "it performance metrics",
        "metrics for system performance",
    ],

    # Chapter IV: IT and Information Security Risk Management
    "conduct_it_risk_review": [
        "periodically review and update risk management policy",
        "periodic review of it related risks",
        "review it related risks",
        "it risk review",
        "risk management policy shall include it related risks",
        "review and update risk management",
        "annual it risk review",
    ],
    "establish_it_risk_framework": [
        "establish it and information security risk management framework",
        "it and information security risk management framework",
        "implement it risk management framework",
        "robust it risk management",
        "information security risk management",
    ],
    "establish_information_security_policy": [
        "establish information security policy and cyber security policy",
        "put in place information security policy",
        "information security policy",
        "cyber security policy",
        "cyber crisis management plan",
        "ccmp",
        "establish is policy",
    ],
    "appoint_ciso": [
        "appoint ciso",
        "designate chief information security officer",
        "appoint chief information security officer",
        "ciso shall be designated",
        "senior executive designated as ciso",
    ],
    "conduct_risk_assessment": [
        "conduct risk assessment",
        "conduct risk assessment and review security infrastructure",
        "risk assessment for information assets",
        "review security infrastructure",
        "security policies shall be reviewed annually",
        "annual security review",
        "review security policies at least annually",
    ],
    "conduct_va": [
        "conduct vulnerability assessment",
        "vulnerability assessment shall be conducted",
        "va shall be conducted",
        "perform vulnerability assessment",
        "carry out vulnerability assessment",
        "conduct vapt",
        "vapt shall be conducted",
    ],
    "conduct_pt": [
        "conduct penetration testing",
        "penetration testing shall be conducted",
        "pt shall be conducted",
        "perform penetration testing",
        "penetration test",
    ],
    "establish_incident_response": [
        "establish incident response and recovery management",
        "put in place incident response",
        "cyber incident response",
        "incident response and recovery management policy",
        "incident response procedures",
        "written incident response procedures",
        "cyber incident response policy",
    ],
    # Merged from report_incident + report_incident_to_rbi
    "report_incident": [
        "report incident",
        "report to rbi",
        "incident reporting",
        "report incident to rbi",
        "reported to rbi",
        "shall be reported to rbi",
        "notify rbi of incidents",
        "pro-actively notify rbi",
        "incident reporting to rbi",
        "notify cert-in",
    ],

    # Chapter V: Business Continuity and Disaster Recovery
    "establish_bcp_policy": [
        "establish business continuity plan and disaster recovery policy",
        "maintain business continuity plan and disaster recovery policy",
        "put in place bcp and dr policy",
        "adopt best practices for business continuity plan",
        "bcp policy",
    ],
    "conduct_dr_drill": [
        "conduct disaster recovery drill",
        "conduct dr drill",
        "disaster recovery drills shall be conducted",
        "dr drills",
        "conduct dr exercise",
        "dr testing",
        "periodicity of dr drills",
        "half-yearly dr drill",
        "dr drill shall be conducted",
    ],
    "establish_dr_management": [
        "establish disaster recovery management",
        "dr management",
        "disaster recovery management",
        "ensure dr architecture is robust",
        "dr architecture and procedures",
        "backup data and periodically restore",
    ],

    # Chapter VI: IS Audit
    "conduct_is_audit": [
        "conduct is audit",
        "information systems audit",
        "is audit",
        "put in place is audit policy",
        "is audit policy",
        "conduct information systems audit",
        "risk-based audit approach",
        "continuous auditing approach",
    ],

    # DPSS-specific retained entries
    "terminate_inactive_sessions": [
        "terminate inactive sessions",
        "automatic session termination",
        "inactive sessions must be terminated",
        "session timeout",
        "automatically terminated",
        "limit lock and terminate sessions",
    ],
    "enforce_cooling_period": [
        "enforce cooling period",
        "cooling period shall be enforced",
        "minimum cooling period",
        "enforce waiting period",
        "cooling period",
        "12-hour cooling period",
    ],
}

# ── Resource catalog ──────────────────────────────────────────────────────────
# Rule: each alias belongs to exactly ONE key.
# cyber_incidents is separate from incident_reports.
# audit_trails alias lives only under audit_logs.

RESOURCES: dict[str, list[str]] = {
    "critical_it_applications": [
        "critical it applications",
        "critical it apps",
        "critical applications",
        "critical it systems",
        "critical information systems",
        "it applications",
        "business products",
        "it environment",
    ],
    "critical_systems_dmz": [
        "critical systems in dmz",
        "critical systems in the dmz",
        "dmz critical systems",
        "systems in dmz",
        "dmz systems",
        "de-militarized zone systems",
        "critical systems in the de-militarized zone",
        "systems in the dmz having customer interface",
        "critical information systems and systems in dmz",
        "critical information systems and systems in dmz with customer interface",
    ],
    "information_assets": [
        "information assets",
        "information asset",
        "it assets",
        "hardware and software",
        "data and information systems",
        "information systems",
        "it infrastructure",
    ],
    "audit_logs": [
        "audit logs",
        "audit trails",
        "system activity logs",
        "all system activities",
        "logs",
        "system logs",
        "audit and system logs",
    ],
    "privileged_accounts": [
        "privileged accounts",
        "privileged user accounts",
        "privileged users",
        "privileged access",
        "elevated system access entitlements",
        "personnel with elevated access",
    ],
    "payment_systems": [
        "payment systems",
        "payment system applications",
        "payment applications",
        "payment system applications and databases",
        "digital payment systems",
    ],
    "mobile_email_credentials": [
        "mobile number or email address",
        "mobile number",
        "email address",
        "mobile/email credentials",
        "transaction authentication credentials",
        "registered mobile number",
        "mobile number or email id linked to payment instrument",
    ],
    "crypto_algorithms": [
        "cryptographic algorithms",
        "crypto algorithms",
        "encryption algorithms",
        "key length algorithms and cipher suites",
        "key length, algorithms and cipher suites",
        "cipher suites",
        "transmission channels",
        "data in transit and at rest",
        "sensitive data",
    ],
    # incident_reports: confirmed events being formally reported
    "incident_reports": [
        "incident reports",
        "incident report",
        "cybersecurity incidents",
        "cybersecurity incident",
        "security incidents",
        "security incident",
        "breach of security",
        "cybersecurity incidents or breach of security",
        "incidents",
        "incident",
    ],
    # cyber_incidents: detected/potential threats (separate from incident_reports)
    "cyber_incidents": [
        "cyber incidents",
        "unusual incidents",
        "unusual cyber incidents",
        "cyber security events",
        "security events",
        "cyber threats",
        "cyber attacks",
        "cyber-attack",
    ],
    "dr_systems": [
        "disaster recovery systems",
        "dr systems",
        "dr plan",
        "disaster recovery plan",
        "dr infrastructure",
        "disaster recovery site",
        "dr and dc sites",
        "data centre and disaster recovery sites",
    ],
    "risk_management_policy": [
        "risk management policy",
        "it risk management policy",
        "enterprise risk management policy",
        "operational risk management policy",
        "it related risks",
        "cyber security related risks",
    ],
    "information_security_policy": [
        "information security policy",
        "cyber security policy",
        "is policy",
        "cyber crisis management plan",
        "ccmp",
        "security policies",
    ],
    "it_governance_framework": [
        "it governance framework",
        "it governance structure",
        "governance structure and processes",
        "it strategy",
        "it strategic planning",
    ],
    "third_party_arrangements": [
        "third party arrangements",
        "third-party service providers",
        "vendors",
        "outsourced services",
        "supply chain",
        "it outsourcing",
        "vendor ecosystem",
    ],
    "data_centre": [
        "data centre",
        "data center",
        "primary data centre",
        "pdc",
        "dc and dr sites",
    ],
    "it_resources": [
        "it resources",
        "it resources and infrastructure",
        "information systems and infrastructure",
        "it capacity",
        "service delivery channels",
        "it infrastructure capacity",
    ],
    "source_code": [
        "source code",
        "application source code",
        "critical application source code",
        "source code escrow",
        "software applications",
    ],
    "business_continuity_plan": [
        "business continuity plan",
        "bcp",
        "bcp policy",
        "business continuity management",
    ],
}


# ── Public API ────────────────────────────────────────────────────────────────

def subject_keys() -> list[str]:
    return list(SUBJECTS.keys())


def action_keys() -> list[str]:
    return list(ACTIONS.keys())


def resource_keys() -> list[str]:
    return list(RESOURCES.keys())


def get_subject_aliases(key: str) -> list[str]:
    return SUBJECTS.get(key, [])


def get_action_aliases(key: str) -> list[str]:
    return ACTIONS.get(key, [])


def get_resource_aliases(key: str) -> list[str]:
    return RESOURCES.get(key, [])


def _build_alias_table(catalog: dict[str, list[str]]) -> dict[str, str]:
    """Build reverse alias -> canonical key lookup.
    Raises ValueError at import time if any duplicate aliases exist.
    """
    table: dict[str, str] = {}
    for canonical, aliases in catalog.items():
        for alias in aliases:
            key = alias.lower().strip()
            if key in table:
                raise ValueError(
                    f"Duplicate alias '{alias}' claimed by both "
                    f"'{table[key]}' and '{canonical}' — fix catalog.py"
                )
            table[key] = canonical
    return table


# Raises ValueError at import time if duplicates exist — catches errors early
SUBJECT_ALIASES = _build_alias_table(SUBJECTS)
ACTION_ALIASES = _build_alias_table(ACTIONS)
RESOURCE_ALIASES = _build_alias_table(RESOURCES)
