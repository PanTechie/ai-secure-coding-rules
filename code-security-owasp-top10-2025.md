# 🛡️ Code Security Rules — OWASP Top 10:2025

> **Version:** 1.0.0
> **Based on:** [OWASP Top 10:2025](https://owasp.org/Top10/2025/)
> **Last updated:** February 2026
> **Usage:** Place this file in `.claude/rules/` in your repository.

---

## General Instructions

When generating, reviewing, or refactoring code, **always apply the following security rules** based on the OWASP Top 10:2025. Treat each rule as mandatory. When in doubt between convenience and security, **prioritize security**.

---

## A01:2025 — Broken Access Control

Access control must ensure users cannot act outside their intended permissions. This is the most prevalent vulnerability, found in virtually every tested application. Includes SSRF (Server-Side Request Forgery), absorbed into this category in 2025.

### Mandatory rules

- **Deny by default** — All access must be denied unless explicitly permitted. Never assume a resource is public.
- **Verify authorization server-side** — Every operation that accesses or modifies data must verify the authenticated user's permissions on the server, never on the client only.
- **Use centralized access control** — Implement a single, reusable authorization mechanism. Avoid scattered and duplicated permission logic.
- **Protect direct object references (IDOR)** — Never expose internal IDs without validation. Always verify the authenticated user has permission to access the requested resource.
- **Disable directory listing** — Web servers must not list directory contents. Remove sensitive metadata (`.git`, `.env`, backups) from deployments.
- **Implement rate limiting** — Protect APIs and controllers against automated abuse, especially on authentication and destructive operation endpoints.
- **Invalidate tokens on logout** — JWT tokens and sessions must be invalidated server-side on logout. Prefer short-lived tokens with refresh mechanisms.
- **Protect against SSRF** — Validate and sanitize all user-supplied URLs. Use allowlists for permitted domains/IPs. Block requests to internal addresses (`127.0.0.1`, `169.254.x.x`, `10.x.x.x`, `metadata.google.internal`, etc.).
- **Apply restrictive CORS** — Configure CORS only for explicitly trusted origins. Never use `Access-Control-Allow-Origin: *` on authenticated APIs.
- **Log access failures** — Every unauthorized access attempt must be logged and should trigger alerts when suspicious patterns are detected.

### Example — Authorization check

```python
# ❌ INSECURE — trusts only the URL ID
@app.route("/api/invoices/<invoice_id>")
def get_invoice(invoice_id):
    return db.get_invoice(invoice_id)

# ✅ SECURE — verifies ownership server-side
@app.route("/api/invoices/<invoice_id>")
@require_auth
def get_invoice(invoice_id):
    invoice = db.get_invoice(invoice_id)
    if invoice.owner_id != current_user.id:
        audit_log.warning(f"Access denied: user={current_user.id} invoice={invoice_id}")
        abort(403)
    return invoice
```

---

## A02:2025 — Security Misconfiguration

Insecure configurations are found in virtually every tested application. Rose from #5 (2021) to #2 (2025), reflecting the growing complexity of modern environments.

### Mandatory rules

- **No default credentials** — Change all default passwords, keys, and tokens before deployment. This includes admin panels, databases, and messaging services.
- **Disable unnecessary features** — Remove unused functionality, ports, services, pages, and frameworks from production.
- **Configure security headers** — Always include: `Content-Security-Policy`, `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`, `Strict-Transport-Security`, `Referrer-Policy`, `Permissions-Policy`.
- **Handle errors without leaking information** — Production error messages must never expose stack traces, software versions, file paths, or internal details.
- **Automate hardening** — Use reproducible processes (IaC, scripts, pipelines) for environment configuration. Never manually configure production servers.
- **Separate environments** — Development, staging, and production must have distinct credentials and configurations with different access controls.
- **Audit cloud configurations** — Verify permissions on S3 buckets, Azure Blobs, and GCS. Never leave storage public without explicit intent.
- **Disable XML External Entities (XXE)** — Disable DTDs and external entities in all XML parsers.
- **Keep software updated** — Apply security patches regularly across all stack components (OS, runtime, frameworks, libraries).

### Example — Security headers

```python
# ✅ Security middleware (Flask example)
@app.after_request
def set_security_headers(response):
    response.headers["Content-Security-Policy"] = "default-src 'self'; script-src 'self'"
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Strict-Transport-Security"] = "max-age=63072000; includeSubDomains; preload"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
    return response
```

---

## A03:2025 — Software Supply Chain Failures ⚡ NEW

New category in 2025 (expanded from "Vulnerable and Outdated Components"). Covers the entire software supply chain: dependencies, build pipelines, malicious packages, and compromised components.

### Mandatory rules

- **Use only trusted sources** — Download dependencies only from official registries (npm, PyPI, Maven Central, crates.io). Verify package authenticity.
- **Pin dependency versions** — Use lockfiles (`package-lock.json`, `poetry.lock`, `Cargo.lock`, `go.sum`) and commit them. Never use unrestricted ranges in production.
- **Audit dependencies regularly** — Run `npm audit`, `pip audit`, `cargo audit`, or equivalents in CI/CD. Treat critical vulnerabilities as blockers.
- **Generate and maintain SBOM** — Produce Software Bill of Materials using tools like CycloneDX or SPDX to track all components.
- **Verify package integrity** — Validate checksums and digital signatures before installation.
- **Minimize dependencies** — Before adding a new dependency, evaluate if it's truly necessary. Prefer well-maintained libraries with active communities.
- **Monitor advisories** — Configure automatic alerts (Dependabot, Renovate, Snyk, or GitHub Security Advisories) for dependency vulnerabilities.
- **Protect CI/CD pipelines** — Treat the pipeline as secure code: access control, managed secrets, isolated runners, and audit logs.
- **Don't blindly run post-install scripts** — Review `postinstall` scripts from unknown dependencies. Consider using `--ignore-scripts` when possible.

### Example — Secure pipeline

```yaml
# ✅ GitHub Actions with hash-pinned actions and auditing
steps:
  - uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683 # v4.2.2
  - uses: actions/setup-node@39370e3970a6d050c480ffad4ff0ed4d3fdee5af # v4.1.0
    with:
      node-version-file: ".nvmrc"
  - run: npm ci # Install exactly from lockfile
  - run: npm audit --audit-level=high # Block on high vulnerabilities
  - run: npm test
```

---

## A04:2025 — Cryptographic Failures

Failures related to missing cryptography, weak algorithms, key exposure, and implementation errors. Dropped from #2 to #4 but remains critical.

### Mandatory rules

- **Classify data by sensitivity** — Identify which data is sensitive (PII, financial, health, credentials) and apply proportional controls.
- **Encrypt data in transit** — Use TLS 1.2+ (preferably TLS 1.3) for all communications. Never transmit sensitive data in clear text.
- **Encrypt data at rest** — Stored sensitive data must be encrypted. Use AES-256-GCM or ChaCha20-Poly1305. Never invent your own algorithm.
- **Use secure password hashing** — Use Argon2id, bcrypt, or scrypt with unique salt per password. Never use MD5, SHA-1, or plain SHA-256 for passwords.
- **Generate keys and IVs correctly** — Use cryptographically secure generators (`secrets` in Python, `crypto.randomBytes` in Node.js, `/dev/urandom`). Never use `Math.random()` for cryptographic purposes.
- **Manage keys securely** — Never hardcode keys or secrets in code. Use secret managers (Vault, AWS Secrets Manager, Azure Key Vault, etc.).
- **Don't store sensitive data unnecessarily** — If you don't need the data, don't store it. Minimize the exposure surface.
- **Disable caching of sensitive data** — Use `Cache-Control: no-store` headers in responses containing sensitive data.
- **Use modern protocols and algorithms** — Disable SSLv3, TLS 1.0/1.1, DES, 3DES, RC4, MD5 for cryptographic purposes.

### Example — Password hashing

```python
# ❌ INSECURE
import hashlib
hashed = hashlib.md5(password.encode()).hexdigest()

# ✅ SECURE
from argon2 import PasswordHasher
ph = PasswordHasher(time_cost=3, memory_cost=65536, parallelism=4)
hashed = ph.hash(password)
# Verification:
ph.verify(hashed, password_attempt)
```

---

## A05:2025 — Injection

Injection vulnerabilities allow attackers to insert malicious code or commands into program inputs. Includes SQL Injection, NoSQL Injection, Command Injection, LDAP Injection, and Cross-Site Scripting (XSS).

### Mandatory rules

- **Use parameterized queries** — ALWAYS use prepared statements or ORMs for database interaction. Never concatenate user input into queries.
- **Validate and sanitize all input** — Validate type, size, format, and range of all user input. Use allowlists when possible, not blocklists.
- **Escape output by context** — Apply appropriate encoding for the rendering context: HTML encoding for HTML, JS encoding for JS, URL encoding for URLs.
- **Use Content Security Policy** — Configure CSP to mitigate XSS. Avoid `unsafe-inline` and `unsafe-eval`.
- **Don't execute system commands with user input** — Avoid `exec()`, `eval()`, `system()`, `child_process.exec()` with untrusted data. If unavoidable, use APIs that accept argument arrays (e.g., `subprocess.run([...])` in Python).
- **Sanitize data for LDAP, XML, XPath** — Apply specific encoding for each interpreter receiving user data.
- **Use ORMs carefully** — Even with ORMs, avoid raw queries with concatenation. Review complex queries to ensure parameterization.
- **Separate data from commands** — At every application layer, maintain clear separation between user-supplied data and executable instructions.

### Example — SQL Injection

```javascript
// ❌ INSECURE — direct concatenation
const query = `SELECT * FROM users WHERE email = '${req.body.email}'`;
db.query(query);

// ✅ SECURE — parameterized query
const query = "SELECT * FROM users WHERE email = $1";
db.query(query, [req.body.email]);
```

---

## A06:2025 — Insecure Design

Category focused on architectural and design flaws that cannot be fixed by perfect implementation alone. Requires threat modeling and secure design from the start.

### Mandatory rules

- **Apply threat modeling** — Before implementing critical features, identify threat actors, attack vectors, and potential impacts.
- **Follow secure design principles** — Apply defense in depth, least privilege, fail-safe defaults, separation of duties, and complete mediation.
- **Limit resource consumption** — Define limits for uploads, requests, processing, and memory allocation per user/session.
- **Implement business limits** — Validate business rules on the server: transaction limits, action frequency, and restrictions by user profile.
- **Separate trust layers** — Define clear trust boundaries between components. Data crossing trust boundaries must always be validated.
- **Use secure design patterns** — Adopt libraries and frameworks that provide built-in protections (e.g., automatic CSRF tokens, template encoding).
- **Write abuse tests** — Beyond functional tests, write tests that simulate malicious usage: excessive payloads, unexpected sequences, and race conditions.

---

## A07:2025 — Authentication Failures

Failures that allow attackers to impersonate legitimate users. Includes credential stuffing, brute force, insecure session management, and weak or absent MFA.

### Mandatory rules

- **Implement multi-factor authentication (MFA)** — Require MFA for sensitive operations and elevated-privilege accounts. Prefer TOTP or WebAuthn/FIDO2 over SMS.
- **No default credentials** — Never deploy with accounts like `admin/admin`, `root/root`, or `test/test`.
- **Implement brute force protection** — Use progressive rate limiting, temporary lockout, and CAPTCHAs after consecutive authentication failures.
- **Require strong passwords** — Minimum 12 characters. Check against compromised password lists (e.g., Have I Been Pwned API). Don't impose arbitrary complexity rules that hurt usability.
- **Protect recovery flows** — Password reset, account recovery, and "forgot password" must be as secure as login. Use single-use tokens with short expiration.
- **Return generic messages** — Login and registration responses must not reveal whether an email/username exists. Use "Invalid credentials" instead of "User not found".
- **Protect tokens and sessions** — Session cookies must have `Secure`, `HttpOnly`, `SameSite=Strict` flags and appropriate expiration.

---

## A08:2025 — Software or Data Integrity Failures

Failures when systems trust code or data without verifying provenance or integrity. Unlike A03 (supply chain), this category focuses on integrity verification at the artifact and data level within your environment.

### Mandatory rules

- **Verify update integrity** — All software receiving automatic updates must verify digital signatures before applying them.
- **Protect against insecure deserialization** — Never deserialize data from untrusted sources without validation. Prefer simple formats (JSON) over formats that execute code (Pickle, Java Serialization, YAML `load()`).
- **Sign build artifacts** — Sign binaries, Docker images, and release packages. Verify signatures before deployment.
- **Validate data from external sources** — Don't trust data from queues, webhooks, or internal APIs without validation. Treat every service boundary as a trust boundary.
- **Use Subresource Integrity (SRI)** — For scripts and styles loaded from CDNs, use `integrity` attributes to verify content hasn't been altered.
- **Protect against mass assignment** — Explicitly define which fields can be modified by users. Use attribute allowlists, never blocklists.

---

## A09:2025 — Security Logging & Alerting Failures

Without adequate logging and alerts, attacks and breaches cannot be detected. Renamed from "Security Logging and Monitoring Failures" to emphasize the importance of alerting as an active response component.

### Mandatory rules

- **Log security events** — Record: logins (success and failure), authorization failures, validation errors, exceptions, and administrative actions.
- **Include context in logs** — Each log entry must contain: timestamp (UTC), user identifier, source IP, attempted action, and result. Never log passwords, tokens, or sensitive data.
- **Protect log integrity** — Logs must not be editable by application users. Use append-only storage or send to an immutable centralized system.
- **Implement alerts** — Configure alerts for suspicious patterns: multiple authentication failures, access from unusual IPs, privilege escalation, and bulk changes.
- **Prevent log injection** — Sanitize user data before including it in logs. Characters like newlines and escapes can manipulate log display.
- **Structure logs** — Use structured format (JSON) to facilitate automated parsing and analysis.

---

## A10:2025 — Mishandling of Exceptional Conditions ⚡ NEW

New category in 2025. Focuses on how systems handle (or fail to handle) errors, abnormal conditions, and unexpected states. Systems that fail insecurely ("fail open") expose data and functionality.

### Mandatory rules

- **Fail secure (fail-closed)** — When an error occurs, the system must deny access by default, not grant it. If the authorization service fails, deny access.
- **Catch specific exceptions** — Never use generic catch (`except Exception`, `catch(e)`) as default. Catch specific exceptions and handle each appropriately.
- **Don't expose internal details in errors** — Error messages for users must be generic. Technical details go only to internal logs.
- **Release resources on error** — Use `finally`, `defer`, `using`, or context managers to ensure connections, locks, and file handles are released.
- **Implement circuit breakers** — For calls to external services, use circuit breakers to prevent failure cascading.
- **Test error paths** — Write specific tests for failure scenarios: timeout, disk full, network unavailable, invalid input, exceeded limits.
- **Define timeouts** — Every network, I/O, and processing operation must have a configured timeout. Operations without timeouts are DoS vectors.

### Example — Fail-secure vs Fail-open

```python
# ❌ INSECURE — fail open: if auth service fails, access is granted
def check_permission(user, resource):
    try:
        return auth_service.is_authorized(user, resource)
    except AuthServiceError:
        return True  # "Fail open" — NEVER DO THIS

# ✅ SECURE — fail secure: error = access denied
def check_permission(user, resource):
    try:
        return auth_service.is_authorized(user, resource)
    except AuthServiceError as e:
        logger.error("Authorization service failure", error=str(e), user=user.id)
        return False  # Fail secure — when in doubt, deny
```

---

## Quick Checklist for Code Review

| #   | Category                           | Key question                                                       |
| --- | ---------------------------------- | ------------------------------------------------------------------ |
| A01 | Broken Access Control              | Does every operation verify permissions on the server?             |
| A02 | Security Misconfiguration          | Are there default credentials, debug enabled, or missing headers?  |
| A03 | Supply Chain Failures              | Are dependencies pinned, audited, and from trusted sources?        |
| A04 | Cryptographic Failures             | Is sensitive data encrypted with modern algorithms?                |
| A05 | Injection                          | Is all user input parameterized/sanitized before use?              |
| A06 | Insecure Design                    | Does the design consider abuse scenarios and have business limits? |
| A07 | Authentication Failures            | Does auth use MFA, brute force protection, and secure sessions?    |
| A08 | Software/Data Integrity Failures   | Are artifacts and data verified for integrity before use?          |
| A09 | Logging & Alerting Failures        | Are security events logged and alerts configured?                  |
| A10 | Mishandling Exceptional Conditions | Does the system fail securely and handle specific exceptions?      |

---

## References

- [OWASP Top 10:2025 — Official Page](https://owasp.org/Top10/2025/)
- [OWASP Cheat Sheet Series](https://cheatsheetseries.owasp.org/)
- [OWASP Application Security Verification Standard (ASVS)](https://owasp.org/www-project-application-security-verification-standard/)
- [CWE — Common Weakness Enumeration](https://cwe.mitre.org/)
- [OWASP Dependency Check](https://owasp.org/www-project-dependency-check/)
- [OWASP CycloneDX (SBOM)](https://cyclonedx.org/)

---

## License

This document is released under [CC BY-SA 4.0](https://creativecommons.org/licenses/by-sa/4.0/). Based on the work of the [OWASP Foundation](https://owasp.org/).
