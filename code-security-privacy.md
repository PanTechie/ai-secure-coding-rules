# 🛡️ Code Security Rules — Privacy Engineering

> **Version:** 1.0.0
> **Based on:** NIST Privacy Framework 1.1, Privacy by Design/Default, GDPR, LGPD, CCPA/CPRA, APPI, PIPEDA, POPIA
> **Last updated:** February 2026
> **Usage:** Place this file in `.claude/rules/` (Claude Code), `.agent/rules/` (Antigravity), or `.cursor/rules/` (Cursor).

---

## Configuration

Select the privacy regulations applicable to your project. The AI assistant must enforce all **universal rules** (always active) plus the regulation-specific rules matching your selection.

```
TARGET_REGULATIONS: LGPD, GDPR
```

Valid values: `GDPR`, `LGPD`, `CCPA`, `APPI`, `PIPEDA`, `POPIA`

Multiple regulations can be selected (comma-separated). When multiple are selected, apply the **most restrictive** requirement where they conflict.

### Quick Regulation Guide

| Regulation    | Jurisdiction              | Consent Model           |       DPO Required?       |              Breach Notification | Max Fine                      |
| ------------- | ------------------------- | ----------------------- | :-----------------------: | -------------------------------: | ----------------------------- |
| **GDPR**      | EU/EEA + extraterritorial | Opt-in (explicit)       | Yes (for specific cases)  |                  72 hours to DPA | €20M or 4% global turnover    |
| **LGPD**      | Brazil + extraterritorial | Opt-in (10 legal bases) |     Yes (Encarregado)     |        "Reasonable time" to ANPD | 2% revenue, up to R$50M       |
| **CCPA/CPRA** | California + thresholds   | Opt-out (sale/sharing)  |            No             |              Varies by state law | $7,500/intentional violation  |
| **APPI**      | Japan + extraterritorial  | Opt-in (prior consent)  |   No (but recommended)    |    Promptly to PPC + individuals | ¥100M (~$680K) for orgs       |
| **PIPEDA**    | Canada (federal/private)  | Informed consent        |            No             |     "As soon as feasible" to OPC | CAD $100K per violation       |
| **POPIA**     | South Africa              | Opt-in (consent)        | Yes (Information Officer) | "As soon as reasonably possible" | R10M (~$550K) or imprisonment |

---

## General Instructions

When generating, reviewing, or refactoring code, **always apply the universal privacy rules below** plus the regulation-specific rules matching `TARGET_REGULATIONS`. These rules implement **Privacy by Design** and **Privacy by Default** principles as code-level requirements. Treat each rule as mandatory. When in doubt between functionality and privacy, **prioritize privacy**.

---

## Section 1 — Data Inventory & Classification `[UNIVERSAL]`

Before processing any personal data, know what you have, where it flows, and why you need it. Maps to NIST PF: Identify-P.

### Mandatory rules

- **Maintain a data inventory model** — Define all personal data types your system processes in a central schema or data catalog. Each field must be annotated with: data category (PII, sensitive, biometric, health, financial, children), purpose of processing, retention period, and legal basis.
- **Classify data at the field level** — Use decorators, annotations, or schema tags to mark personal data fields. This enables automated enforcement of privacy rules throughout the codebase.
- **Map data flows** — Document how personal data enters the system (collection points), where it is stored, which services process it, and where it is transmitted (third parties, cross-border). Keep this mapping in version-controlled documentation.
- **Identify data subjects** — Explicitly define the categories of individuals whose data you process (customers, employees, minors, prospects). Different categories may have different legal protections.

```python
# ✅ SECURE — data classification through model annotations
from enum import Enum
from pydantic import BaseModel, Field
from datetime import datetime

class DataCategory(str, Enum):
    PII = "pii"
    SENSITIVE = "sensitive"
    BIOMETRIC = "biometric"
    HEALTH = "health"
    FINANCIAL = "financial"
    CHILDREN = "children"

class LegalBasis(str, Enum):
    CONSENT = "consent"
    CONTRACT = "contract"
    LEGAL_OBLIGATION = "legal_obligation"
    VITAL_INTEREST = "vital_interest"
    PUBLIC_INTEREST = "public_interest"
    LEGITIMATE_INTEREST = "legitimate_interest"

class UserProfile(BaseModel):
    user_id: str = Field(description="Internal identifier")
    name: str = Field(
        json_schema_extra={
            "privacy": {
                "category": DataCategory.PII,
                "legal_basis": LegalBasis.CONTRACT,
                "retention_days": 365,
                "purpose": "Account management",
            }
        }
    )
    email: str = Field(
        json_schema_extra={
            "privacy": {
                "category": DataCategory.PII,
                "legal_basis": LegalBasis.CONTRACT,
                "retention_days": 365,
                "purpose": "Account management and communication",
            }
        }
    )
    health_data: dict | None = Field(
        default=None,
        json_schema_extra={
            "privacy": {
                "category": DataCategory.HEALTH,
                "legal_basis": LegalBasis.CONSENT,
                "retention_days": 90,
                "purpose": "Health service delivery",
                "requires_explicit_consent": True,
            }
        }
    )
```

```typescript
// ✅ SECURE — TypeScript decorators for privacy classification
function PersonalData(options: {
  category: "pii" | "sensitive" | "biometric" | "health" | "financial";
  purpose: string;
  retentionDays: number;
  legalBasis: string;
}) {
  return function (target: any, propertyKey: string) {
    Reflect.defineMetadata("privacy", options, target, propertyKey);
  };
}

class UserProfile {
  userId: string;

  @PersonalData({
    category: "pii",
    purpose: "Account management",
    retentionDays: 365,
    legalBasis: "contract",
  })
  name: string;

  @PersonalData({
    category: "pii",
    purpose: "Communication",
    retentionDays: 365,
    legalBasis: "contract",
  })
  email: string;
}
```

---

## Section 2 — Data Minimization & Purpose Limitation `[UNIVERSAL]`

Collect only what you need, use it only for stated purposes, and delete it when done. This is the most fundamental privacy principle, shared by every regulation. Maps to NIST PF: Control-P.

### Mandatory rules

- **Collect only necessary data** — Every form field, API parameter, and data collection point must justify its existence against a stated purpose. Remove optional fields that serve no clear business need.
- **Enforce purpose limitation in code** — Data collected for purpose A must not be reused for purpose B without additional legal basis or consent. Implement access controls that enforce purpose boundaries.
- **Default to minimal data** — New features must request the minimum data needed. Checkbox pre-selection, pre-filled sensitive fields, and auto-opt-in are prohibited.
- **Avoid collecting unique device identifiers unnecessarily** — Do not collect IMEI, MAC address, IDFA/GAID, or hardware serial numbers unless strictly needed and disclosed.
- **Pseudonymize where possible** — When data is used for analytics, testing, or non-essential processing, replace direct identifiers with pseudonyms or tokens. Keep the mapping table separately with stricter access controls.

```python
# ❌ INSECURE — collecting unnecessary data
class RegistrationForm(BaseModel):
    email: str
    password: str
    full_name: str
    date_of_birth: date        # Not needed for basic registration
    phone: str                 # Not needed for basic registration
    address: str               # Not needed for basic registration
    social_security: str       # NEVER collect this unless legally required

# ✅ SECURE — minimal data collection
class RegistrationForm(BaseModel):
    email: str
    password: str
    display_name: str  # Only what's needed for account creation
```

---

## Section 3 — Consent Management `[UNIVERSAL + REGULATION-SPECIFIC]`

### Universal rules

- **Record consent with full context** — Store: what was consented to (purpose), when, how (mechanism), the version of the privacy policy at that time, and the subject's identity. Never store consent as a simple boolean.
- **Make consent revocable** — Users must be able to withdraw consent at any time, with the same ease as giving it. Implement a consent management API.
- **Do not process before consent** — When consent is the legal basis, no processing of the data may begin until consent is recorded. This means no tracking pixels, analytics, or cookies before the user acts.
- **Separate consent by purpose** — Consent for marketing is separate from consent for analytics, which is separate from consent for sharing with third parties. No bundled consent.
- **No consent walls** — Access to core services must not be conditioned on consent to unrelated data processing (e.g., "accept marketing cookies to use the app").

```python
# ✅ SECURE — granular consent model
from datetime import datetime
from uuid import uuid4

class ConsentRecord(BaseModel):
    consent_id: str = Field(default_factory=lambda: str(uuid4()))
    user_id: str
    purpose: str            # e.g., "marketing_email", "analytics", "third_party_sharing"
    granted: bool
    timestamp: datetime
    mechanism: str           # e.g., "web_form_v2", "mobile_toggle", "api"
    policy_version: str      # e.g., "privacy-policy-2026-01-15"
    ip_address: str | None = None  # For proof, encrypted at rest
    revoked_at: datetime | None = None

class ConsentService:
    async def grant_consent(self, user_id: str, purpose: str,
                            mechanism: str, policy_version: str) -> ConsentRecord:
        record = ConsentRecord(
            user_id=user_id,
            purpose=purpose,
            granted=True,
            timestamp=datetime.utcnow(),
            mechanism=mechanism,
            policy_version=policy_version,
        )
        await self.store.save(record)
        await self.audit_log.record("consent_granted", record)
        return record

    async def revoke_consent(self, user_id: str, purpose: str) -> None:
        record = await self.store.get_active_consent(user_id, purpose)
        if record:
            record.revoked_at = datetime.utcnow()
            record.granted = False
            await self.store.save(record)
            await self.audit_log.record("consent_revoked", record)
            await self.trigger_data_processing_stop(user_id, purpose)

    async def check_consent(self, user_id: str, purpose: str) -> bool:
        record = await self.store.get_active_consent(user_id, purpose)
        return record is not None and record.granted and record.revoked_at is None
```

### GDPR-specific consent rules `[GDPR]`

- **Consent must be freely given, specific, informed, and unambiguous** — Pre-ticked checkboxes, inactivity, or silence do NOT constitute consent. Affirmative action is required (Article 7).
- **Record the legal basis for every processing operation** — GDPR provides 6 legal bases: consent, contract, legal obligation, vital interests, public task, legitimate interests. Code must enforce which basis applies to each operation.
- **Support withdrawal equal to granting** — If consent was given with one click, withdrawal must also be one click. No hidden settings, multi-step processes, or "call us" to revoke.
- **Children require parental consent** — For information society services, children under 16 (or as low as 13, per member state) require verifiable parental consent (Article 8).

### LGPD-specific consent rules `[LGPD]`

- **Support 10 legal bases** — LGPD provides 10 legal bases (broader than GDPR): consent, legal obligation, public policy execution, research (anonymized), contract execution, exercise of rights in lawsuits, protection of life, health protection, legitimate interest, and credit protection (Article 7).
- **Consent must be written or otherwise demonstrable** — Consent must stand out clearly from other contractual clauses. Generic authorizations are void (Article 8).
- **Specific consent for sensitive data** — Processing of sensitive personal data (racial/ethnic origin, religion, political opinion, health, sex life, genetics, biometrics) requires specific and prominent consent (Article 11).

### CCPA/CPRA-specific rules `[CCPA]`

- **Implement "Do Not Sell or Share My Personal Information"** — Provide a clear, prominent link on the website. When triggered, stop all sale/sharing of that consumer's data with third parties.
- **Support opt-out, not opt-in** — Unlike GDPR/LGPD, CCPA uses an opt-out model for most processing. However, minors under 16 require opt-in, and under 13 require parental opt-in.
- **Honor Global Privacy Control (GPC)** — Detect and respect the `Sec-GPC: 1` HTTP header as a valid opt-out signal for sale/sharing of personal information.
- **No financial incentives for data** — Do not offer discounts or premium services conditioned on consumers waiving privacy rights unless the incentive is reasonably related to data value.

```typescript
// ✅ SECURE — GPC detection middleware [CCPA]
function handleGlobalPrivacyControl(
  req: Request,
  res: Response,
  next: NextFunction,
) {
  const gpcHeader = req.headers["sec-gpc"];
  if (gpcHeader === "1") {
    // Treat as opt-out of sale/sharing
    req.privacyPreferences = {
      ...req.privacyPreferences,
      doNotSell: true,
      doNotShare: true,
      source: "gpc_header",
    };
  }
  next();
}
```

### APPI-specific consent rules `[APPI]`

- **Obtain prior consent for third-party transfers** — APPI requires consent before providing personal data to third parties, with limited exceptions (Article 27).
- **Special rules for cross-border transfers** — Transferring personal data outside Japan requires: consent after informing the subject about the destination country's data protection regime, or the recipient being in a country with equivalent protections, or appropriate safeguards in place (Article 28).
- **Record of third-party provisions** — Maintain records of all third-party data provisions and receipts, including dates, recipient identity, and data categories (Articles 29-30).

### PIPEDA-specific consent rules `[PIPEDA]`

- **Meaningful consent** — Consent must be based on clear, plain-language information about what data is collected, why, and who it's shared with. PIPEDA recognizes both express and implied consent depending on sensitivity.
- **Implied consent is allowed for non-sensitive data** — Unlike GDPR, PIPEDA permits implied consent when a reasonable person would expect the collection and the data is not sensitive.
- **Allow withdrawal at any time** — Organizations must inform individuals of the consequences of withdrawal but must honor it promptly.

### POPIA-specific consent rules `[POPIA]`

- **Consent is voluntary, specific, and informed** — Similar to GDPR. Consent for children (under 18) requires a competent person (parent/guardian) (Section 35).
- **Direct marketing requires explicit opt-in** — Unless there's an existing customer relationship, direct marketing to individuals requires prior consent (Section 69).

---

## Section 4 — Data Subject Rights `[UNIVERSAL + REGULATION-SPECIFIC]`

### Universal rules

- **Implement a Data Subject Request (DSR) API** — Provide programmatic endpoints for all applicable rights. Authenticate the requester, verify identity, process within legal deadlines, and log every request.
- **Automate where possible** — Rights like access, portability, and deletion should be automatable through API calls, not manual processes.
- **Identity verification before fulfillment** — Verify the requester's identity before processing any DSR to prevent unauthorized data disclosure. Use existing authentication or secondary verification.

```python
# ✅ SECURE — centralized DSR handler
from enum import Enum

class DSRType(str, Enum):
    ACCESS = "access"                # Right to access data
    RECTIFICATION = "rectification"  # Right to correct data
    ERASURE = "erasure"              # Right to deletion
    PORTABILITY = "portability"      # Right to data export
    RESTRICTION = "restriction"      # Right to restrict processing
    OBJECTION = "objection"          # Right to object to processing
    OPT_OUT_SALE = "opt_out_sale"    # CCPA: opt-out of sale

class DSRRequest(BaseModel):
    request_id: str = Field(default_factory=lambda: str(uuid4()))
    user_id: str
    request_type: DSRType
    submitted_at: datetime
    identity_verified: bool = False
    fulfilled_at: datetime | None = None
    deadline: datetime  # Calculated per regulation

class DSRService:
    DEADLINES = {
        "GDPR": timedelta(days=30),      # extendable by 60 days
        "LGPD": timedelta(days=15),
        "CCPA": timedelta(days=45),      # extendable by 45 days
        "APPI": timedelta(days=30),      # "without delay"
        "PIPEDA": timedelta(days=30),
        "POPIA": timedelta(days=30),
    }

    async def submit_request(self, user_id: str, request_type: DSRType,
                             regulation: str) -> DSRRequest:
        deadline = datetime.utcnow() + self.DEADLINES[regulation]
        dsr = DSRRequest(
            user_id=user_id,
            request_type=request_type,
            submitted_at=datetime.utcnow(),
            deadline=deadline,
        )
        await self.store.save(dsr)
        await self.notify_privacy_team(dsr)
        return dsr

    async def fulfill_access(self, dsr: DSRRequest) -> dict:
        """Collect all personal data across all services for this user."""
        data = {}
        for service in self.registered_services:
            data[service.name] = await service.export_user_data(dsr.user_id)
        dsr.fulfilled_at = datetime.utcnow()
        await self.store.save(dsr)
        return data

    async def fulfill_erasure(self, dsr: DSRRequest) -> None:
        """Delete or anonymize all personal data for this user."""
        for service in self.registered_services:
            await service.erase_user_data(dsr.user_id)
        # Retain only the DSR record itself (legal obligation)
        dsr.fulfilled_at = datetime.utcnow()
        await self.store.save(dsr)
```

### Right-to-erasure specifics

- **`[GDPR]`** — Right to erasure ("right to be forgotten") under Article 17. Must also notify third parties who received the data.
- **`[LGPD]`** — Right to deletion of data processed with consent (Article 18). Must anonymize or delete.
- **`[CCPA]`** — Right to deletion with limited exceptions (ongoing transaction, security, legal obligation, internal expected uses).
- **`[APPI]`** — Right to request cessation of use or erasure if data is no longer needed or was obtained improperly.
- **`[PIPEDA]`** — Individuals can challenge accuracy and completeness; organizations must correct or annotate records.
- **`[POPIA]`** — Right to request deletion or destruction of personal information (Section 24).

### Right-to-portability specifics

- **`[GDPR]`** — Data must be provided in a structured, commonly used, machine-readable format (JSON, CSV). Must support direct transfer to another controller where technically feasible (Article 20).
- **`[LGPD]`** — Data portability to another service provider (Article 18). Format defined by ANPD.
- **`[CCPA]`** — Must provide data in portable, readily usable format.
- **`[APPI]`** — No explicit portability right, but the 2022 amendments strengthen access rights.

---

## Section 5 — Privacy by Design & Default `[UNIVERSAL]`

Privacy by Design (PbD) means embedding privacy into every stage of the development lifecycle. Privacy by Default means the strictest privacy settings apply automatically without user action. Maps to NIST PF: Protect-P.

### Mandatory rules

- **Default to privacy-preserving settings** — Every feature ships with the most restrictive privacy configuration. Users opt in to less privacy, never opt out to get more.
- **Build privacy into architecture** — Privacy is a system design requirement, not a feature added later. Include privacy requirements in design documents, architecture decision records, and user stories.
- **Apply data minimization at the schema level** — Database schemas should not contain fields "just in case." Every column storing personal data must be traceable to a purpose and retention policy.
- **Separate identifiers from profile data** — Store authentication identifiers (email, phone) separately from behavioral/profile data. Link them through internal pseudonymous IDs.
- **Implement privacy impact assessments (PIA/DPIA) before launch** — Any new feature that processes personal data, introduces new data categories, or uses automated decision-making requires a documented privacy impact assessment before deployment.
- **Anonymize data for non-essential uses** — Analytics, testing, development, and ML training must use anonymized or synthetic data, not production personal data.

```python
# ✅ SECURE — Privacy by Default in feature flags
class FeatureConfig:
    ANALYTICS_TRACKING = False      # Disabled by default
    THIRD_PARTY_SHARING = False     # Disabled by default
    PERSONALIZED_ADS = False        # Disabled by default
    LOCATION_TRACKING = False       # Disabled by default
    BIOMETRIC_AUTH = False          # Disabled by default

    # Only core functionality is enabled by default
    ACCOUNT_MANAGEMENT = True
    CORE_SERVICE = True
```

---

## Section 6 — Data Retention & Deletion `[UNIVERSAL + REGULATION-SPECIFIC]`

### Universal rules

- **Define retention periods for every data category** — Every type of personal data must have a documented maximum retention period tied to its purpose. When the purpose expires, the data must be deleted or anonymized.
- **Implement automated retention enforcement** — Build scheduled jobs that identify and delete/anonymize data that has exceeded its retention period. Never rely on manual cleanup.
- **Soft-delete with hard-delete follow-through** — Soft-delete is acceptable for grace periods (e.g., 30 days for account recovery), but must be followed by irreversible hard deletion after the grace period.
- **Delete from all locations** — Deletion must cover: primary database, replicas, caches, search indices, backups (mark for non-restoration), logs, analytics systems, and third-party services.
- **Anonymize when deletion is impossible** — If data cannot be fully deleted (e.g., part of an aggregate report), anonymize it by removing all identifiers and linkability.

```python
# ✅ SECURE — automated retention enforcement
from datetime import datetime, timedelta

RETENTION_POLICIES = {
    "user_profile": timedelta(days=365),          # 1 year after account closure
    "transaction_records": timedelta(days=2555),   # 7 years (legal/tax)
    "marketing_consent": timedelta(days=730),      # 2 years
    "session_logs": timedelta(days=90),            # 90 days
    "support_tickets": timedelta(days=365),        # 1 year after resolution
    "analytics_events": timedelta(days=180),       # 6 months
}

async def enforce_retention():
    """Run daily to delete expired data."""
    for data_type, retention in RETENTION_POLICIES.items():
        cutoff = datetime.utcnow() - retention
        expired_records = await db.find_expired(data_type, cutoff)
        for record in expired_records:
            await delete_from_all_systems(record)
            await audit_log.record("retention_deletion", {
                "data_type": data_type,
                "record_id": record.id,
                "expired_at": cutoff.isoformat(),
            })
```

### Regulation-specific retention rules

- **`[GDPR]`** — Storage limitation principle (Article 5(1)(e)). Data must be kept only as long as necessary for the purposes. No fixed maximum, but purpose must justify duration.
- **`[LGPD]`** — Data must be deleted after the end of the processing period, except when required by law, research (anonymized), transfer to third party (with legal basis), or exclusive use by the controller (anonymized) (Article 16).
- **`[CCPA]`** — As of CPRA amendments, businesses must disclose retention periods and not retain data longer than reasonably necessary.
- **`[APPI]`** — Personal data must be deleted without delay when no longer needed for the specified purpose (Article 22).

---

## Section 7 — Cross-Border Data Transfers `[REGULATION-SPECIFIC]`

### GDPR `[GDPR]`

- **Adequacy decisions** — Transfers to countries with EU adequacy decisions (e.g., Japan, UK, Canada, South Korea) are permitted without additional safeguards.
- **Standard Contractual Clauses (SCCs)** — When transferring to non-adequate countries, implement EU SCCs and conduct a Transfer Impact Assessment (TIA).
- **No transfer without legal mechanism** — Code must enforce data residency when required: configure cloud regions, block API calls that would send personal data to non-approved regions.

### LGPD `[LGPD]`

- **International transfer requires justification** — Permitted to countries with adequate protection, via contractual clauses, or with specific and prominent consent (Article 33).
- **ANPD guidance** — Follow ANPD resolutions on standard contractual clauses and adequacy determinations as they evolve.

### CCPA `[CCPA]`

- **No explicit cross-border restriction** — CCPA does not restrict international transfers, but sale/sharing rules apply regardless of destination.

### APPI `[APPI]`

- **Strict cross-border transfer rules** — Require informed consent specifying the destination country's privacy framework, or transfer to PPC-recognized countries, or contractual safeguards equivalent to APPI (Article 28).

### PIPEDA `[PIPEDA]`

- **Accountability remains with the Canadian org** — Organizations are responsible for personal data transferred to third parties, including those in other countries. Must ensure comparable protection via contractual means.

### POPIA `[POPIA]`

- **Transfer only to adequate jurisdictions** — Or with binding corporate rules, consent, or contractual necessity (Section 72).

```python
# ✅ SECURE — data residency enforcement
ALLOWED_REGIONS = {
    "GDPR": {"eu-west-1", "eu-central-1", "eu-north-1"},
    "LGPD": {"sa-east-1", "eu-west-1"},  # Brazil + adequate countries
    "POPIA": {"af-south-1", "eu-west-1"},
}

class DataResidencyMiddleware:
    def __init__(self, regulation: str):
        self.allowed = ALLOWED_REGIONS.get(regulation, set())

    async def validate_storage(self, data_category: str, target_region: str):
        if self.allowed and target_region not in self.allowed:
            raise DataResidencyViolation(
                f"Cannot store {data_category} in {target_region}. "
                f"Allowed regions: {self.allowed}"
            )
```

---

## Section 8 — Breach Notification `[UNIVERSAL + REGULATION-SPECIFIC]`

### Universal rules

- **Implement breach detection and response** — Build monitoring for unauthorized data access, exfiltration patterns, anomalous queries, and privilege escalation. Alert the security team immediately.
- **Maintain a breach response runbook** — Document the step-by-step process: detect → contain → assess scope → notify authorities → notify individuals → remediate → post-mortem.
- **Log access to personal data** — Every read, write, export, and deletion of personal data must be logged with: who, what, when, from where. This enables breach scope assessment.

### Regulation-specific notification timelines

- **`[GDPR]`** — Notify supervisory authority within **72 hours** of becoming aware of a breach involving personal data risk. Notify individuals "without undue delay" if high risk (Articles 33-34).
- **`[LGPD]`** — Notify ANPD and data subjects within a **"reasonable time"** (ANPD recommends 2 business days). Must include: nature of data, affected subjects, risks, measures taken (Article 48).
- **`[CCPA]`** — No specific breach notification timeline in CCPA itself, but California Civil Code §1798.82 requires notification "in the most expedient time possible" without unreasonable delay.
- **`[APPI]`** — Notify the Personal Information Protection Commission (PPC) and affected individuals **promptly** (2022 amendments made this mandatory for certain breaches).
- **`[PIPEDA]`** — Notify OPC and affected individuals **"as soon as feasible"** after determining a breach poses a "real risk of significant harm" (RROSH).
- **`[POPIA]`** — Notify the Information Regulator and data subjects **"as soon as reasonably possible"** after discovery (Section 22).

```python
# ✅ SECURE — breach notification workflow
class BreachNotifier:
    DEADLINES = {
        "GDPR": timedelta(hours=72),
        "LGPD": timedelta(hours=48),      # ANPD recommendation
        "CCPA": timedelta(hours=72),       # Best practice
        "APPI": timedelta(days=3),         # "Promptly"
        "PIPEDA": timedelta(hours=72),     # "As soon as feasible"
        "POPIA": timedelta(hours=72),      # "As soon as reasonably possible"
    }

    async def handle_breach(self, breach: BreachReport):
        for reg in breach.applicable_regulations:
            deadline = breach.detected_at + self.DEADLINES[reg]
            await self.schedule_notification(
                regulation=reg,
                breach=breach,
                deadline=deadline,
                authority=self.get_authority(reg),
            )
            await self.audit_log.record("breach_notification_scheduled", {
                "breach_id": breach.id,
                "regulation": reg,
                "deadline": deadline.isoformat(),
            })
```

---

## Section 9 — Data Protection Officer / Encarregado `[REGULATION-SPECIFIC]`

- **`[GDPR]`** — DPO required for: public authorities, organizations whose core activities involve large-scale systematic monitoring, or large-scale processing of sensitive data (Article 37).
- **`[LGPD]`** — Encarregado (DPO) is required. Must be named publicly and be the point of contact for data subjects and the ANPD (Article 41).
- **`[POPIA]`** — Information Officer must be registered with the Information Regulator (Section 55).
- **`[APPI]` `[PIPEDA]` `[CCPA]`** — No mandatory DPO, but recommended as best practice.

### Code-level implication

- **Expose DPO contact in privacy interfaces** — Privacy policies, consent forms, and DSR pages must display the DPO/Encarregado contact information.
- **Route DSRs to the DPO workflow** — All data subject requests must be routed through the designated privacy officer's workflow for oversight.

---

## Section 10 — Automated Decision-Making & Profiling `[REGULATION-SPECIFIC]`

### GDPR `[GDPR]`

- **Right to not be subject to solely automated decisions** — If a decision significantly affects a person and is made solely by automated processing (including profiling), the individual has the right to obtain human intervention, express their point of view, and contest the decision (Article 22).
- **Explain the logic** — Provide meaningful information about the logic involved in automated decisions. This doesn't require exposing source code, but the reasoning must be understandable.
- **DPIA required for profiling** — Automated profiling that produces legal effects requires a Data Protection Impact Assessment before deployment.

### LGPD `[LGPD]`

- **Right to review automated decisions** — Data subjects can request review of decisions made solely by automated processing that affect their interests, including profiling (Article 20).
- **Provide explanation criteria** — The controller must provide clear and adequate information about the criteria and procedures used for automated decisions (Article 20, §1).

### CCPA `[CCPA]`

- **Opt-out of automated decision-making** — CPRA regulations require businesses that use automated decision-making technology for profiling to allow consumers to opt out (effective per CPPA enforcement).
- **Access to logic** — Consumers may request meaningful information about the logic involved in profiling decisions.

```python
# ✅ SECURE — explainable automated decision with human review
class AutomatedDecision(BaseModel):
    decision_id: str
    user_id: str
    decision_type: str            # e.g., "credit_scoring", "content_moderation"
    input_factors: dict           # Data points used in the decision
    output: str                   # The decision result
    confidence: float             # Model confidence score
    explanation: str              # Human-readable explanation
    requires_human_review: bool   # Flag for significant decisions
    human_reviewed: bool = False
    human_reviewer: str | None = None
    created_at: datetime

class DecisionService:
    SIGNIFICANT_DECISION_TYPES = {
        "credit_scoring", "insurance_pricing", "employment_screening",
        "loan_approval", "benefit_eligibility",
    }

    async def make_decision(self, user_id: str, decision_type: str,
                            input_data: dict) -> AutomatedDecision:
        result = await self.model.predict(input_data)

        decision = AutomatedDecision(
            decision_id=str(uuid4()),
            user_id=user_id,
            decision_type=decision_type,
            input_factors=self._sanitize_factors(input_data),
            output=result.label,
            confidence=result.confidence,
            explanation=self._generate_explanation(result),
            requires_human_review=decision_type in self.SIGNIFICANT_DECISION_TYPES,
            created_at=datetime.utcnow(),
        )

        if decision.requires_human_review:
            await self.queue_for_review(decision)

        return decision
```

---

## Section 11 — Children's Data Protection `[REGULATION-SPECIFIC]`

- **`[GDPR]`** — Parental consent required for children under 16 (member states may lower to 13) for information society services (Article 8).
- **`[LGPD]`** — Processing of children's and adolescents' data must be in their best interest. Requires specific and prominent consent from a parent or legal guardian (Article 14).
- **`[CCPA]`** — Opt-in required for consumers aged 13-16 for sale/sharing. Parental opt-in for under 13 (Section 1798.120(c-d)).
- **`[APPI]`** — No specific age threshold, but personal data of minors is treated as requiring special care.
- **`[PIPEDA]`** — Requires "meaningful consent" considering the age and capacity of the individual. OPC guidance emphasizes additional protections for minors.
- **`[POPIA]`** — Children under 18 require consent from a "competent person" (parent/guardian). Processing is only justified if in the child's best interest (Section 35).

### Code-level rules

- **Implement age verification** — Collect and verify age at registration when processing children's data. Do not rely on self-reported age alone for high-risk processing.
- **Default to maximum protection for unknown age** — If age cannot be determined, apply the most restrictive rules (assume child).
- **Disable profiling and targeted content for minors** — Automated decision-making, behavioral advertising, and algorithmic content recommendations must be disabled for users identified as minors.

---

## Section 12 — Technical Privacy Controls `[UNIVERSAL]`

### Mandatory rules

- **Encrypt personal data at rest** — Use AES-256 or equivalent for all stored personal data. Use envelope encryption with managed keys (AWS KMS, Azure Key Vault, GCP Cloud KMS).
- **Encrypt in transit** — All data transmission must use TLS 1.2+. Disable older protocols.
- **Implement field-level encryption for sensitive categories** — Health, biometric, financial, and children's data must have an additional layer of field-level encryption beyond storage-level encryption.
- **Use tokenization for cross-system references** — When personal data must be referenced across systems, use opaque tokens instead of actual identifiers.
- **Implement access logging and monitoring** — Log all access to personal data stores with user identity, timestamp, operation type, and affected records. Alert on anomalous access patterns.
- **Apply data masking in non-production environments** — Development, staging, QA, and demo environments must use masked or synthetic data, never production personal data.
- **Implement row-level security** — Database access should enforce that users/services can only query records they are authorized to access.

```python
# ✅ SECURE — field-level encryption for sensitive data
from cryptography.fernet import Fernet
import base64, os

class FieldEncryption:
    def __init__(self, key_provider):
        self.key_provider = key_provider

    def encrypt_field(self, value: str, data_category: str) -> str:
        key = self.key_provider.get_key(data_category)
        f = Fernet(key)
        return f.encrypt(value.encode()).decode()

    def decrypt_field(self, encrypted: str, data_category: str) -> str:
        key = self.key_provider.get_key(data_category)
        f = Fernet(key)
        return f.decrypt(encrypted.encode()).decode()

# Usage: different keys for different sensitivity levels
encryption = FieldEncryption(key_provider)
encrypted_ssn = encryption.encrypt_field("123-45-6789", "financial")
encrypted_health = encryption.encrypt_field("diagnosis data", "health")
```

---

## Section 13 — Cookie & Tracking Compliance `[REGULATION-SPECIFIC]`

### GDPR + ePrivacy `[GDPR]`

- **Prior consent for non-essential cookies** — No analytics, advertising, or tracking cookies may be set before the user provides affirmative consent. Only strictly necessary cookies (session, security, load balancing) are exempt.
- **Granular cookie categories** — Provide separate opt-in for: strictly necessary (no consent needed), functional, analytics, advertising/targeting.
- **Reject must be as easy as accept** — Cookie banners must give equal prominence to "Accept" and "Reject" buttons. No dark patterns.

### LGPD `[LGPD]`

- **Cookie consent required** — LGPD requires consent for non-essential cookies. ANPD guidelines align with GDPR approach.

### CCPA `[CCPA]`

- **"Do Not Sell/Share" applies to tracking** — Third-party cookies that share data with ad networks constitute "sharing." Must honor opt-out via cookie banner and GPC header.

### APPI `[APPI]`

- **Cookie consent increasingly expected** — While APPI doesn't explicitly regulate cookies, the 2022 amendments increased obligations for "personally referable information." Best practice: treat tracking similarly to GDPR.

---

## Section 14 — Privacy in AI/ML Systems `[UNIVERSAL]`

Maps to NIST Privacy Framework 1.1 Section 1.2.2 (AI and Privacy Risk).

### Mandatory rules

- **Do not train on personal data without legal basis** — ML models must not be trained on personal data unless consent is granted for that specific purpose, or another legal basis applies.
- **Implement differential privacy for analytics and training** — When using aggregated personal data for analytics or ML training, apply differential privacy techniques to prevent individual re-identification.
- **Prevent model memorization** — Validate that trained models do not memorize and regurgitate personal data from training sets. Use membership inference testing.
- **Document AI data provenance** — For every ML model, document: what personal data was used in training, the legal basis, how consent was obtained, and whether the data was anonymized.
- **Enable right to erasure from models** — When a data subject requests deletion and their data was used in training, document the impact assessment and retrain if feasible, or document why retraining is disproportionate.
- **Conduct AI privacy impact assessments** — Before deploying any AI system that processes personal data, conduct a dedicated privacy impact assessment covering: data sources, inference risks, profiling impact, and automated decision consequences.

---

## Quick Reference Table

### Universal Principles (All Regulations)

| Principle          | Key Rule                          | Code Impact                                        |
| ------------------ | --------------------------------- | -------------------------------------------------- |
| Data Minimization  | Collect only what's needed        | Minimal form fields, no "just in case" columns     |
| Purpose Limitation | Use data only for stated purposes | Purpose-tagged fields, access controls per purpose |
| Storage Limitation | Delete when purpose expires       | Automated retention enforcement jobs               |
| Privacy by Design  | Embed privacy into architecture   | Privacy-first defaults, separation of identifiers  |
| Privacy by Default | Strictest settings by default     | Features ship opted-out, not opted-in              |
| Security           | Protect with appropriate measures | Encryption, access logging, masking                |
| Accountability     | Demonstrate compliance            | Consent records, audit logs, PIAs                  |

### Regulation Comparison Matrix

| Capability                   |    GDPR     |   LGPD   |  CCPA   |   APPI   |     PIPEDA     |  POPIA  |
| ---------------------------- | :---------: | :------: | :-----: | :------: | :------------: | :-----: |
| Consent model                |   Opt-in    |  Opt-in  | Opt-out |  Opt-in  |    Informed    | Opt-in  |
| Right to access              |     ✅      |    ✅    |   ✅    |    ✅    |       ✅       |   ✅    |
| Right to deletion            |     ✅      |    ✅    |   ✅    |    ✅    |    Partial     |   ✅    |
| Right to portability         |     ✅      |    ✅    |   ✅    | Limited  |       ❌       |   ❌    |
| Automated decision opt-out   |     ✅      |    ✅    |   ✅    |    ❌    |       ❌       |   ❌    |
| DPO/Encarregado required     | Conditional |    ✅    |   ❌    |    ❌    |       ❌       |   ✅    |
| Breach notification deadline |     72h     |   ~48h   |  ASAP   | Promptly |      ASAP      |  ASAP   |
| Children's age threshold     | 16 (or 13)  |    18    |  16/13  |   N/A    |   Contextual   |   18    |
| Cross-border restrictions    |   Strict    | Moderate |  None   |  Strict  | Accountability | Strict  |
| Cookie consent               |  Required   | Required | Opt-out | Evolving |  Recommended   | Implied |

---

## Cross-Reference: Privacy ↔ Other Security Files

| Privacy Requirement            | Related Security File                                            |
| ------------------------------ | ---------------------------------------------------------------- |
| Encryption at rest/transit     | `code-security-secrets.md` — Key management                      |
| Access control & authorization | `code-security-owasp-top10-2025.md` — A01 Broken Access Control  |
| Input validation (DSR APIs)    | `code-security-cwe-top25-2025.md` — CWE-20 Input Validation      |
| API security for DSR endpoints | `code-security-owasp-api-top10-2023.md` — BOLA, Rate Limiting    |
| Logging & monitoring           | `code-security-infrastructure.md` — Logging & Monitoring section |
| Mobile data protection         | `code-security-mobile.md` — MASVS-STORAGE, MASVS-PRIVACY         |

---

## References

- [NIST Privacy Framework 1.0](https://www.nist.gov/privacy-framework)
- [NIST Privacy Framework 1.1 IPD](https://nvlpubs.nist.gov/nistpubs/CSWP/NIST.CSWP.40.ipd.pdf)
- [GDPR Full Text](https://eur-lex.europa.eu/eli/reg/2016/679/oj)
- [LGPD Full Text (Lei 13.709/2018)](https://www.planalto.gov.br/ccivil_03/_ato2015-2018/2018/lei/l13709.htm)
- [CCPA/CPRA Full Text](https://oag.ca.gov/privacy/ccpa)
- [APPI (Japan) — PPC Overview](https://www.ppc.go.jp/en/)
- [PIPEDA Full Text](https://laws-lois.justice.gc.ca/eng/acts/P-8.6/)
- [POPIA Full Text](https://popia.co.za/)
- [Privacy by Design — 7 Foundational Principles](https://iapp.org/resources/article/privacy-by-design-the-7-foundational-principles/)
- [CNIL Cookie Guidelines](https://www.cnil.fr/en/cookies-and-other-tracking-devices)

---

## License

This file is released under [CC BY-SA 4.0](https://creativecommons.org/licenses/by-sa/4.0/). Based on publicly available legal texts and frameworks. This file does NOT constitute legal advice. Consult qualified legal professionals for compliance assessments.
