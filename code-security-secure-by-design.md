# 🛡️ Code Security Rules — Secure by Design (SbD)

> **Version:** 1.0.0
> **Based on:** CISA Secure by Design Principles (2023/2024), CISA Secure by Design Pledge (2024), NIST SP 800-218 — Secure Software Development Framework (SSDF) v1.1/v1.2
> **Last updated:** February 2026
> **Usage:** Place this file in `.claude/rules/` (Claude Code), `.agent/rules/` or `.agent/skills/security-sbd/` (Antigravity), or `.cursor/rules/` (Cursor).

---

## What is Secure by Design?

Secure by Design (SbD) is a philosophy where security is a **core business requirement built into every phase of the SDLC** — not bolted on after development. The burden of security shifts from customers to manufacturers.

This file translates SbD principles into **actionable rules for AI-assisted development**, covering architecture decisions, default configurations, development practices, and vulnerability management.

### Source Frameworks

| Framework                                  | Published        | Scope                                  |
| ------------------------------------------ | ---------------- | -------------------------------------- |
| CISA "Shifting the Balance" — 3 Principles | Oct 2023 (v2)    | Strategic SbD philosophy               |
| CISA Secure by Design Pledge — 7 Goals     | May 2024         | Measurable manufacturer commitments    |
| NIST SP 800-218 (SSDF) v1.1                | Feb 2022         | Secure development lifecycle practices |
| NIST SP 800-218 Rev. 1 (SSDF v1.2)         | Dec 2025 (draft) | Updated practices incl. AI/ML          |

---

## Principle 1 — Take Ownership of Customer Security Outcomes

The software must be secure out of the box. Security should not depend on the customer's ability to configure, patch, or purchase add-ons.

### 1.1 Secure Defaults

- **Ship secure by default** — Every feature must launch with the most secure configuration that is reasonably usable. The customer should not need a hardening guide to be safe.
- **Enable MFA by default** — Multi-factor authentication must be enabled or strongly prompted for all users, especially administrators. SSO and MFA must be available at no extra cost.
- **No default passwords** — Systems must never ship with default, shared, or blank passwords. Force unique credential creation during initial setup.
- **No default admin accounts** — Do not ship with pre-configured admin users. Require the first administrator to be created during setup with strong credentials.
- **Disable insecure protocols by default** — Disable HTTP (use HTTPS only), disable SSHv1, disable TLS < 1.2, disable SNMP v1/v2, disable Telnet. Secure protocols only.
- **Enable logging and audit trails by default** — Security-relevant events must be logged out of the box, not as a paid add-on. Include authentication events, authorization failures, and configuration changes.
- **Enable security headers by default** — Web applications must ship with `Strict-Transport-Security`, `Content-Security-Policy`, `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`, and `Referrer-Policy` already configured.
- **Least privilege by default** — Default user roles must have the minimum permissions necessary. Admin permissions must require explicit elevation.
- **Restrict network exposure by default** — Services should listen on localhost or private interfaces by default, not `0.0.0.0`. External exposure must require explicit configuration.

```python
# ❌ INSECURE — insecure defaults that depend on customer hardening
class AppConfig:
    DEBUG = True
    SECRET_KEY = "changeme"
    SESSION_COOKIE_SECURE = False
    SESSION_COOKIE_HTTPONLY = False
    MFA_REQUIRED = False
    DEFAULT_ADMIN_PASSWORD = "admin"
    ALLOWED_HOSTS = ["*"]
    CORS_ALLOW_ALL_ORIGINS = True

# ✅ SECURE BY DESIGN — safe defaults, no hardening needed
class AppConfig:
    DEBUG = False
    SECRET_KEY = os.environ["SECRET_KEY"]  # Fail if not set
    SESSION_COOKIE_SECURE = True
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = "Lax"
    MFA_REQUIRED = True
    # No default admin — created during first-run setup wizard
    ALLOWED_HOSTS = os.environ["ALLOWED_HOSTS"].split(",")
    CORS_ALLOW_ALL_ORIGINS = False
    CORS_ALLOWED_ORIGINS = os.environ.get("CORS_ORIGINS", "").split(",")
```

### 1.2 Secure Product Development Practices

- **Threat model every feature** — Before writing code, identify threats using STRIDE, PASTA, or attack trees. Document threats, mitigations, and residual risk. Update when the design changes. Aligns with SSDF PW.1.
- **Define security requirements alongside functional requirements** — Every user story or feature spec must include security acceptance criteria. "As an admin, I can create users" must include "with enforced MFA and audit logging." Aligns with SSDF PO.3.
- **Integrate security into every sprint** — Security is not a phase. Every sprint must include: security review of new code, dependency update check, and regression testing of security controls.
- **Use secure-by-default frameworks** — Choose frameworks that are secure by default (e.g., React for XSS auto-escaping, Django for CSRF protection, Rust for memory safety). Avoid frameworks that require manual security hardening.
- **Maintain a security architecture document** — Document trust boundaries, data flows, authentication mechanisms, and encryption points. Keep it updated as the system evolves.

### 1.3 Automatic Security Patches

- **Support automatic updates** — Products must support automatic security patches. Make the update path frictionless for customers.
- **Decouple security patches from feature releases** — Security fixes must be releasable independently, without forcing customers to adopt new features or breaking changes.
- **Provide extended security support** — Define and publish end-of-life dates. Provide security patches for supported versions for a reasonable period.
- **Monitor customer patch adoption** — Track what versions customers are running. Proactively reach out to customers on vulnerable versions.

---

## Principle 2 — Embrace Radical Transparency and Accountability

Be honest about security posture. Publish vulnerabilities, share root causes, and help the industry learn from your mistakes.

### 2.1 Vulnerability Disclosure

- **Publish a Vulnerability Disclosure Policy (VDP)** — Authorize public testing, commit to no legal action against good-faith researchers, provide a clear reporting channel, and allow coordinated disclosure. Publish a `security.txt` file at `/.well-known/security.txt`.
- **Issue CVEs promptly** — For all critical/high vulnerabilities, issue CVE records in a timely manner with accurate CWE (root cause) and CPE (affected products) fields. Do not delay CVE publication for marketing reasons.
- **Perform root cause analysis** — For every significant vulnerability, identify the CWE root cause. Track CWE trends over time to measure whether entire classes of vulnerabilities are being reduced.
- **Publish security advisories** — When vulnerabilities are patched, publish clear advisories describing: what was affected, what the impact was, what the fix is, and what customers should do.

```
# ✅ SECURE BY DESIGN — /.well-known/security.txt
Contact: mailto:security@example.com
Contact: https://example.com/security/report
Encryption: https://example.com/.well-known/pgp-key.txt
Acknowledgments: https://example.com/security/hall-of-fame
Preferred-Languages: en, pt
Canonical: https://example.com/.well-known/security.txt
Policy: https://example.com/security/vdp
Hiring: https://example.com/careers/security
Expires: 2027-02-28T00:00:00.000Z
```

### 2.2 Transparency Practices

- **Publish an SBOM** — Generate and make available a Software Bill of Materials (SBOM) in a standard format (CycloneDX or SPDX) for every release.
- **Document security design decisions** — Publish or make available the security architecture, including encryption algorithms, authentication flows, and trust boundaries.
- **Share security metrics** — Where possible, share vulnerability trend data (e.g., CWE distribution over time, mean time to patch, percentage of auto-updated customers).
- **Be transparent about incidents** — When breaches occur, communicate promptly and clearly: what happened, what was affected, what you're doing about it, and what customers should do.

---

## Principle 3 — Lead From the Top

Security must be a business priority, driven by executive leadership, not just an engineering concern.

### 3.1 Organizational Practices

- **Assign a product security owner** — Someone with authority and budget must be accountable for product security outcomes.
- **Include security in performance goals** — Developer, team, and executive performance goals must include security outcomes (e.g., vulnerability class reduction, secure defaults adoption, patch adoption rate).
- **Fund security tooling** — SAST, DAST, SCA, secrets scanning, fuzzing, and dependency management are not optional. Budget for them.
- **Train developers regularly** — All developers must receive secure coding training aligned to the technologies they use, at least annually. Aligns with SSDF PO.2.

---

## CISA Secure by Design Pledge — 7 Implementation Goals

These goals translate the 3 principles above into measurable development practices.

### Goal 1 — Increase MFA Usage

- **Offer MFA at no extra cost** — MFA must be available for all users, not only premium tiers.
- **Support modern MFA methods** — TOTP, WebAuthn/FIDO2, and push-based authentication. Avoid SMS-only MFA where possible due to SIM-swapping risk.
- **Prompt for MFA enrollment** — On first login and periodically, prompt users to enable MFA if not yet enrolled.
- **Enforce MFA for privileged accounts** — Admin, operator, and service accounts must require MFA with no opt-out.
- **Provide recovery codes** — Generate backup codes during MFA setup so users are not locked out.

```typescript
// ✅ SECURE BY DESIGN — MFA enforcement middleware
async function requireMFA(req: Request, res: Response, next: NextFunction) {
  const user = req.user;

  if (!user.mfaEnabled) {
    // Redirect to MFA setup, not denial
    return res.redirect(
      "/security/setup-mfa?returnTo=" + encodeURIComponent(req.originalUrl),
    );
  }

  if (!req.session.mfaVerified) {
    return res.redirect(
      "/security/verify-mfa?returnTo=" + encodeURIComponent(req.originalUrl),
    );
  }

  next();
}

// Enforce on all admin routes
app.use("/admin", requireMFA);
// Strongly prompt on sensitive user actions
app.use("/settings/security", requireMFA);
app.use("/settings/billing", requireMFA);
```

### Goal 2 — Eliminate Default Passwords

- **Never ship default passwords** — No default credentials in any component: application, database, admin panel, API key, IoT device.
- **Force initial credential creation** — First-run setup must require the user to create unique credentials.
- **Enforce password strength** — Minimum 12 characters. Check against known breached password lists (e.g., `have-i-been-pwned` k-anonymity API). Block common patterns.
- **Detect and alert on default credentials** — If legacy components have default credentials, detect and force rotation on first use.

```python
# ✅ SECURE BY DESIGN — first-run setup forces credential creation
class FirstRunSetup:
    def create_admin(self, username: str, password: str) -> Admin:
        if self._is_breached_password(password):
            raise ValueError("This password has appeared in known data breaches. Choose a different one.")
        if len(password) < 12:
            raise ValueError("Password must be at least 12 characters.")
        if username.lower() in ("admin", "root", "administrator", "user"):
            raise ValueError("Choose a non-generic username.")

        admin = Admin(
            username=username,
            password_hash=argon2.hash(password),
            mfa_required=True,  # Force MFA on admin
            must_change_password=False,  # Already set by user
        )
        return admin

    def _is_breached_password(self, password: str) -> bool:
        sha1 = hashlib.sha1(password.encode()).hexdigest().upper()
        prefix, suffix = sha1[:5], sha1[5:]
        resp = requests.get(f"https://api.pwnedpasswords.com/range/{prefix}")
        return suffix in resp.text
```

### Goal 3 — Reduce Entire Classes of Vulnerability

This is the highest-impact SbD goal: eliminate systemic weaknesses by construction, not by patching individual bugs.

- **Use memory-safe languages** — For new projects and components, prefer Rust, Go, Java, C#, Python, TypeScript over C/C++. For existing C/C++ code, publish a memory safety roadmap.
- **Use parameterized queries exclusively** — Eliminate SQL injection by construction. Never build SQL strings. Use ORM/query builder parameterization, including for `.raw()` calls.
- **Use context-aware output encoding** — Eliminate XSS by construction. Use frameworks with automatic escaping (React, Angular, Jinja2 `|e`). Never use `dangerouslySetInnerHTML`, `v-html`, `{!! !!}`, or `|safe` with user data.
- **Validate and sanitize all input at the boundary** — Use schema validation (JSON Schema, Zod, Pydantic) at API entry points. Reject invalid input before it reaches business logic.
- **Use type-safe deserialization** — Eliminate unsafe deserialization by never using `pickle.loads()`, `yaml.load()` (use `safe_load`), Java `ObjectInputStream` with untrusted data. Use typed, schema-validated formats (JSON with validation, Protobuf).
- **Eliminate command injection** — Never pass user input to shell commands. Use language-native libraries instead of shelling out.
- **Eliminate path traversal** — Canonicalize all file paths, validate they're within the expected base directory, and reject `..` sequences.
- **Track CWE trends** — Analyze CVE root causes (CWEs) over time. Set measurable targets (e.g., "reduce XSS by 50% this year").

```rust
// ✅ SECURE BY DESIGN — memory safety by language choice
// Using Rust eliminates buffer overflows, use-after-free, and data races
// at compile time — no runtime overhead, no need for manual review

fn process_input(data: &[u8]) -> Result<String, Error> {
    // Bounds checking is automatic — no buffer overflow possible
    let text = std::str::from_utf8(data)?;

    // Ownership system prevents use-after-free at compile time
    let processed = text.trim().to_lowercase();

    // No null pointers — Option<T> forces explicit handling
    let config = load_config().ok_or(Error::MissingConfig)?;

    Ok(format!("{}: {}", config.prefix, processed))
}
```

### Goal 4 — Increase Security Patch Installation

- **Make patches easy to apply** — One-click or automatic updates. Minimize downtime and manual steps.
- **Decouple security patches from feature releases** — Customers should not need to adopt new features to get security fixes.
- **Communicate patch urgency** — Use CVSS scores and clear language ("Critical — apply immediately" vs "Low — apply at next maintenance window").
- **Provide patch verification** — Let customers verify they're running the patched version (version endpoint, health check, CLI command).

### Goal 5 — Publish a Vulnerability Disclosure Policy

- **Authorize public testing** — The VDP must explicitly permit good-faith security research on your products.
- **No legal threats** — Commit to not pursuing legal action against researchers acting in good faith within the VDP scope.
- **Provide clear reporting channels** — Dedicated email (security@), web form, or integration with platforms like HackerOne/Bugcrowd.
- **Publish `security.txt`** — Machine-readable VDP description at `/.well-known/security.txt` per RFC 9116.
- **Acknowledge and credit researchers** — Respond to reports promptly (target: acknowledge within 48 hours) and credit researchers publicly (with consent).

### Goal 6 — Transparent CVE Reporting

- **Include CWE in every CVE** — Every CVE record must identify the root cause weakness using CWE identifiers. This enables industry-wide tracking of vulnerability class trends.
- **Include CPE in every CVE** — Every CVE record must identify affected products and versions using CPE identifiers.
- **Issue CVEs for all critical/high vulnerabilities** — Whether found internally or externally. Do not suppress CVEs.
- **Publish CVEs promptly** — Do not delay CVE publication beyond the coordinated disclosure window.

### Goal 7 — Improve Intrusion Detection Evidence

- **Provide audit logs at no extra cost** — Customers must be able to gather evidence of intrusions without purchasing additional products or tiers.
- **Log security-critical events** — Authentication success/failure, authorization decisions, user creation/deletion, permission changes, data access, configuration changes.
- **Support log forwarding** — Enable customers to forward logs to their own SIEM (syslog, webhook, S3, or API).
- **Include sufficient detail** — Logs must include: timestamp (UTC), actor identity, action performed, resource affected, source IP, and result (success/failure).

```python
# ✅ SECURE BY DESIGN — structured security audit logging
import structlog
from datetime import datetime, timezone

security_log = structlog.get_logger("security.audit")

def log_security_event(
    event_type: str,
    actor: str,
    action: str,
    resource: str,
    result: str,  # "success" | "failure" | "denied"
    source_ip: str,
    details: dict | None = None,
):
    security_log.info(
        event_type,
        timestamp=datetime.now(timezone.utc).isoformat(),
        actor=actor,
        action=action,
        resource=resource,
        result=result,
        source_ip=source_ip,
        details=details or {},
    )

# Usage examples — these must be called from the actual handlers
log_security_event("auth", "user@example.com", "login", "/auth/login", "success", "1.2.3.4")
log_security_event("authz", "user@example.com", "access_denied", "/admin/users", "denied", "1.2.3.4")
log_security_event("config", "admin@example.com", "modify", "/settings/security", "success", "5.6.7.8",
                   details={"field": "mfa_required", "old": False, "new": True})
```

---

## NIST SSDF (SP 800-218) — Development Lifecycle Practices

The SSDF provides the operational framework that makes SbD principles actionable across the entire SDLC.

### PO — Prepare the Organization

Ensure people, processes, and technology are ready for secure development.

- **PO.1 — Define security roles** — Assign clear ownership for: secure architecture review, code security review, dependency management, vulnerability response, and incident communication.
- **PO.2 — Train all personnel** — Developers must receive secure coding training specific to their tech stack. Update training when new vulnerability classes emerge.
- **PO.3 — Define security requirements** — Maintain a catalog of security requirements derived from regulations, threat models, and industry standards. Include them in every feature design.
- **PO.4 — Secure the development environment** — Protect build systems, code repositories, artifact registries, and CI/CD pipelines. Enforce MFA on all development tools. See `code-security-iac.md` for CI/CD security rules.
- **PO.5 — Implement supporting tooling** — Deploy and maintain: SAST (static analysis), DAST (dynamic analysis), SCA (software composition analysis), secrets scanning, and fuzzing tools integrated into CI/CD.

### PS — Protect the Software

Protect source code, build artifacts, and releases from tampering and unauthorized access.

- **PS.1 — Protect code from unauthorized access** — Enforce branch protection, require signed commits, use role-based access to repositories. See OWASP CI/CD CICD-SEC-01.
- **PS.2 — Verify software release integrity** — Sign all release artifacts (binaries, containers, packages). Publish hashes. Use Sigstore/Cosign for container images, GPG for packages.
- **PS.3 — Archive and protect releases** — Maintain immutable release archives. Use content-addressable storage. Protect build provenance records (SLSA framework).

```yaml
# ✅ SECURE BY DESIGN — signed releases with provenance
# GitHub Actions workflow for SLSA Level 3 provenance
- name: Generate SLSA provenance
  uses: slsa-framework/slsa-github-generator/.github/workflows/generator_generic_slsa3.yml@v2.0.0
  with:
    base64-subjects: "${{ steps.hash.outputs.hashes }}"
    upload-assets: true
```

### PW — Produce Well-Secured Software

Minimize vulnerabilities during design, coding, building, and testing.

- **PW.1 — Design software to meet security requirements** — Conduct threat modeling for new features and architectural changes. Document security design decisions. Use security reference architectures.
- **PW.2 — Review designs for security** — Peer review security-relevant design decisions before implementation begins. Involve a security-knowledgeable reviewer.
- **PW.3 — Reuse well-secured software** — Prefer mature, well-maintained, security-audited libraries over writing custom implementations. Especially for: cryptography, authentication, session management, input validation, and HTML sanitization.
- **PW.4 — Follow secure coding practices** — Apply the rules from `security-essentials.md` and the detailed security files in this collection. Use linters and SAST tools configured to enforce these rules automatically.
- **PW.5 — Configure the build process securely** — Use locked dependency versions, verify checksums, build in isolated environments, and generate SBOM as part of the build.
- **PW.6 — Review code for security** — All code changes must go through peer review. Security-sensitive changes (auth, crypto, input validation, authorization) must have a security-focused review.
- **PW.7 — Test for security** — Run SAST, DAST, SCA, and secrets scanning in CI/CD. Integrate fuzzing for parsers and input handlers. Run penetration tests on releases.
- **PW.8 — Configure software for secure deployment** — Ship with secure default configurations (see Principle 1). Provide deployment guides that reinforce secure settings.
- **PW.9 — Generate SBOM** — Every build must produce a Software Bill of Materials (CycloneDX or SPDX) listing all direct and transitive dependencies with versions.

### RV — Respond to Vulnerabilities

Identify, remediate, and learn from vulnerabilities in released software.

- **RV.1 — Identify and confirm vulnerabilities** — Monitor for vulnerability reports from: VDP, bug bounties, automated scanning, dependency advisories, and internal testing. Triage within 24 hours for critical issues.
- **RV.2 — Assess, prioritize, and remediate** — Use CVSS and exploitability context (EPSS, KEV catalog) to prioritize. Set SLA targets: Critical ≤ 7 days, High ≤ 30 days, Medium ≤ 90 days.
- **RV.3 — Analyze root causes** — For every vulnerability, identify the CWE root cause. Ask: "What development practice, if it existed, would have prevented this?" Feed lessons back into PO (training), PW (tooling), and security requirements.

```python
# ✅ SECURE BY DESIGN — vulnerability remediation SLA
REMEDIATION_SLA = {
    "critical": timedelta(days=7),    # CVSS 9.0-10.0 or in CISA KEV
    "high":     timedelta(days=30),   # CVSS 7.0-8.9
    "medium":   timedelta(days=90),   # CVSS 4.0-6.9
    "low":      timedelta(days=180),  # CVSS 0.1-3.9
}

def check_sla_compliance(vulnerability) -> bool:
    sla = REMEDIATION_SLA[vulnerability.severity]
    elapsed = datetime.now(timezone.utc) - vulnerability.reported_at
    return elapsed <= sla
```

---

## Secure by Design Checklist — Architecture & Design Review

Use this checklist when designing new features, reviewing PRs, or auditing existing systems.

### Secure Defaults

| #   | Check                                            | Pass? |
| --- | ------------------------------------------------ | :---: |
| 1   | MFA enabled or strongly prompted by default?     |   ☐   |
| 2   | No default/shared/blank passwords anywhere?      |   ☐   |
| 3   | Security headers configured out of the box?      |   ☐   |
| 4   | Logging enabled by default with security events? |   ☐   |
| 5   | HTTPS enforced, insecure protocols disabled?     |   ☐   |
| 6   | Least-privilege default roles?                   |   ☐   |
| 7   | Network services bound to localhost by default?  |   ☐   |

### Eliminate Vulnerability Classes

| #   | Check                                                    | CWE Class                   | Pass? |
| --- | -------------------------------------------------------- | --------------------------- | :---: |
| 8   | Parameterized queries (no string concatenation)?         | CWE-89 SQLi                 |   ☐   |
| 9   | Context-aware output encoding (auto-escaping framework)? | CWE-79 XSS                  |   ☐   |
| 10  | No shell commands with user input?                       | CWE-78 OS Command Injection |   ☐   |
| 11  | Memory-safe language or memory safety plan?              | CWE-787, CWE-416            |   ☐   |
| 12  | Type-safe deserialization only?                          | CWE-502                     |   ☐   |
| 13  | Path canonicalization and base directory check?          | CWE-22 Path Traversal       |   ☐   |
| 14  | Schema validation at API boundary?                       | CWE-20 Input Validation     |   ☐   |

### Supply Chain & Build Integrity

| #   | Check                                         | Pass? |
| --- | --------------------------------------------- | :---: |
| 15  | Dependency versions pinned with lockfile?     |   ☐   |
| 16  | Dependencies scanned for CVEs in CI?          |   ☐   |
| 17  | SBOM generated for every release?             |   ☐   |
| 18  | Release artifacts signed?                     |   ☐   |
| 19  | Build environment isolated and reproducible?  |   ☐   |
| 20  | Third-party integrations reviewed and scoped? |   ☐   |

### Transparency & Response

| #   | Check                                   | Pass? |
| --- | --------------------------------------- | :---: |
| 21  | `security.txt` published?               |   ☐   |
| 22  | VDP published and accessible?           |   ☐   |
| 23  | CVE process defined (CWE + CPE fields)? |   ☐   |
| 24  | Audit logs available to customers?      |   ☐   |
| 25  | Remediation SLAs defined and tracked?   |   ☐   |

---

## Cross-Reference: SbD ↔ Other Security Files

| SbD Requirement                              | Related Security File                                           |
| -------------------------------------------- | --------------------------------------------------------------- |
| Eliminate injection classes (Goal 3)         | `code-security-owasp-top10-2025.md` — A05 Injection             |
| Eliminate memory safety classes (Goal 3)     | `code-security-cwe-top25-2025.md` — Category 2 Memory Safety    |
| MFA implementation details (Goal 1)          | `code-security-owasp-asvs-5.0.md` — V6 Authentication           |
| Secrets management (Principle 1)             | `code-security-secrets.md` — All sections                       |
| CI/CD pipeline security (SSDF PS)            | `code-security-iac.md` — Section 4 CI/CD                        |
| API authorization patterns (Principle 1)     | `code-security-owasp-api-top10-2023.md` — API1 BOLA             |
| Privacy-by-design defaults (Principle 1)     | `code-security-privacy.md` — Section 5 Privacy by Design        |
| LLM output as untrusted (Goal 3)             | `code-security-owasp-llm-top10-2025.md` — LLM05 Output Handling |
| Mobile secure storage defaults (Principle 1) | `code-security-mobile.md` — MASVS-STORAGE                       |

---

## References

- [CISA Secure by Design — Main Page](https://www.cisa.gov/securebydesign)
- [CISA "Shifting the Balance of Cybersecurity Risk" — Principles (v2, Oct 2023)](https://www.cisa.gov/resources-tools/resources/secure-by-design)
- [CISA Secure by Design Pledge — 7 Goals (May 2024)](https://www.cisa.gov/securebydesign/pledge)
- [CISA Secure by Demand Guide (Aug 2024)](https://www.cisa.gov/sites/default/files/2024-08/SecureByDemandGuide_080624_508c.pdf)
- [NIST SP 800-218 — SSDF v1.1 (Feb 2022)](https://csrc.nist.gov/pubs/sp/800/218/final)
- [NIST SP 800-218 Rev. 1 — SSDF v1.2 Draft (Dec 2025)](https://csrc.nist.gov/pubs/sp/800/218/r1/ipd)
- [NIST SP 800-218A — SSDF for Generative AI](https://csrc.nist.gov/projects/ssdf)
- [SLSA Framework — Supply Chain Integrity](https://slsa.dev/)
- [RFC 9116 — security.txt](https://www.rfc-editor.org/rfc/rfc9116)

---

## License

This file is released under [CC BY-SA 4.0](https://creativecommons.org/licenses/by-sa/4.0/). Based on public guidance from CISA and NIST.
