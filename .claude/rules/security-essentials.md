# 🛡️ Security Rules — Essential (Always Active)

> **Purpose:** Condensed, always-on security rules applied automatically to every code generation, review, and refactoring task. For detailed examples, audits, and in-depth guidance, invoke the full security skill files.
> **Version:** 1.0.0
> **Last updated:** February 2026

---

## Injection Prevention

- Always use **parameterized queries** for SQL — never concatenate or interpolate user input into SQL strings, including in ORM `.raw()` methods.
- **Encode output contextually** — HTML entity encoding for HTML body, JS encoding for script contexts, URL encoding for URL params. Use framework auto-escaping (React, Jinja2, Go html/template).
- Never pass user input to **shell commands** — avoid `os.system()`, `subprocess(shell=True)`, backticks. Use library alternatives or argument arrays.
- Never use **`eval()`**, `exec()`, `Function()`, or `setTimeout(string)` with any data derived from user input.
- **Sanitize rich HTML** with allowlist-based sanitizers (DOMPurify, Bleach). Never use regex for HTML sanitization.

## Authentication & Session

- **Hash passwords** with bcrypt, scrypt, or Argon2id. Never use MD5, SHA-1, or SHA-256 alone for passwords.
- Enforce **MFA** for admin and sensitive operations. Support TOTP or WebAuthn.
- Generate session tokens with **cryptographically secure randomness** (minimum 128 bits entropy).
- **Invalidate sessions** on logout, password change, and privilege escalation. Set idle and absolute timeouts.
- Use **short-lived JWTs** with refresh tokens. Validate `iss`, `aud`, `exp`, and `alg` (reject `none`).

## Authorization & Access Control

- **Deny by default** — all access denied unless explicitly permitted.
- Verify authorization **server-side on every request** — never rely on client-side checks alone.
- Use **centralized authorization** — single reusable mechanism, not scattered checks.
- Validate the authenticated user **owns the resource** (prevent IDOR) — derive user identity from the session/token, not from request parameters.
- Apply **rate limiting** on authentication endpoints and destructive operations.

## Cryptography

- Use **AES-256-GCM** for symmetric encryption, **RSA-2048+/ECDSA P-256+** for asymmetric, **SHA-256+** for hashing.
- **Never implement custom cryptography** — use vetted libraries (libsodium, OpenSSL, Web Crypto API, java.security).
- Generate **unique IVs/nonces** per encryption operation. Never reuse IV with the same key.
- Enforce **TLS 1.2+** for all network communication. Disable TLS 1.0, 1.1, SSLv3.

## Secrets Management

- **Never hardcode secrets** in source code, environment variables in Dockerfiles, IaC files, or CI/CD configs.
- Use **secrets managers** (Vault, AWS Secrets Manager, Azure Key Vault, GCP Secret Manager) for all credentials.
- **Rotate** all secrets, tokens, and API keys on a regular schedule (90 days maximum for credentials).
- Run **secret scanning** (Gitleaks, TruffleHog) in pre-commit hooks and CI pipelines.
- Maintain a `.gitignore` that blocks: `.env`, `*.pem`, `*.key`, `*.secret`, `*.tfvars`, `*.tfstate`.

## Input Validation

- Validate **all input server-side** — type, length, range, format, and allowed characters.
- Use **allowlists** (what IS valid), not denylists (what isn't).
- Validate at **entry point** (controller/handler), before business logic.
- **Reject** invalid input entirely — do not attempt to "fix" malformed data.
- Set **maximum sizes** for request bodies, file uploads, string lengths, array sizes, and JSON nesting depth.

## File & Upload Handling

- Validate file types by **magic bytes** (content inspection), not by extension or Content-Type header.
- **Rename uploaded files** server-side (UUID). Never preserve user-supplied filenames.
- Store uploads **outside the web root**. Serve through a handler with `Content-Disposition: attachment`.
- **Canonicalize paths** and verify they are within the expected base directory before any file operation (prevent path traversal).

## Data Protection & Privacy

- Collect only **necessary data** — every field must be traceable to a stated purpose.
- Default to **privacy-preserving settings** — features ship opted-out, not opted-in.
- Implement **data subject rights** APIs (access, deletion, portability) when handling personal data.
- Define and enforce **retention periods** — automated deletion when purpose expires.
- **Encrypt personal data at rest** (AES-256) and **in transit** (TLS 1.2+). Apply field-level encryption for sensitive categories (health, biometric, financial).
- Never expose **stack traces, SQL errors, or internal paths** in production responses.

## API Security

- Enforce **object-level authorization** on every endpoint (prevent BOLA).
- Implement **rate limiting and throttle** per user/IP/API key.
- Use **explicit response schemas** — never serialize entire database objects. Return only required fields.
- Validate request bodies against a **strict schema** (reject unknown properties).
- Set **timeouts** on all external calls, database queries, and I/O operations.

## Dependency & Supply Chain

- **Pin dependency versions** and use lockfiles. Verify checksums.
- **Scan dependencies** for known vulnerabilities in CI (npm audit, pip-audit, cargo audit, Dependabot).
- Use **private/internal registries** to proxy external packages. Claim internal names in public registries (prevent dependency confusion).
- **Review new dependencies** before adding — assess maintenance, popularity, and security posture.

## Container & Infrastructure

- **Never run containers as root** — use `USER nonroot` in Dockerfiles. Set `runAsNonRoot: true` in Kubernetes.
- **Drop all capabilities** (`cap_drop: ALL`), add back only what's needed. Set `readOnlyRootFilesystem: true`.
- **Pin image versions** to digests (`@sha256:...`). Never use `:latest` in production.
- Set **resource limits** (CPU, memory) on every container/pod.
- Use **multi-stage builds** — separate build dependencies from runtime images.
- **Scan images** for CVEs in CI. Block deployment of images with CRITICAL/HIGH vulnerabilities.
- Sign container images and **verify signatures** before deployment.

## Kubernetes Specific

- Set **SecurityContext** on every pod: `allowPrivilegeEscalation: false`, `readOnlyRootFilesystem: true`, `capabilities.drop: [ALL]`, `seccompProfile: RuntimeDefault`.
- Set `automountServiceAccountToken: false` unless the pod calls the K8s API.
- Apply **default-deny NetworkPolicies** (ingress + egress) per namespace.
- Follow **RBAC least privilege** — no `*` wildcards, no `cluster-admin` bindings, no `default` service account for workloads.
- Encrypt **etcd at rest**. Use external secrets operators (ESO, Vault) instead of plain K8s Secrets.
- Enforce **Pod Security Standards** (`restricted` for production).

## CI/CD Pipeline

- Require **code review + passing CI checks** before merge. No direct pushes to main/production.
- Use **OIDC federation** (e.g., GitHub Actions → AWS) instead of long-lived static credentials.
- **Pin third-party actions** to commit SHAs, not mutable tags.
- Set **explicit minimal permissions** per job (`permissions: contents: read`).
- **Isolate fork/PR builds** from production secrets.
- Protect **pipeline configuration files** from modification by untrusted contributors.

## IaC (Terraform/CloudFormation/Pulumi)

- Never hardcode secrets in `.tf`, `.yaml`, or `.ts` files — reference **secrets managers**.
- Encrypt **state files** (S3+KMS, GCS+CMEK). Enable state locking.
- Default to **encryption enabled** and **public access blocked** on all storage and database resources.
- Use `prevent_destroy` / `DeletionPolicy: Retain` on **critical resources** (databases, encryption keys, storage).
- Run **IaC scanning** (Checkov, tfsec, cfn_nag) in CI before apply.
- Tag all resources with `environment`, `owner`, and `managed-by`.

## Cloud Provider

- Enable **audit logging** (CloudTrail, Activity Log, Cloud Audit Logs) on all accounts.
- **Block 0.0.0.0/0** on management ports (SSH, RDP, database ports) in all security groups/firewall rules.
- Enforce **MFA on all human accounts**. Do not create root/owner access keys.
- Use **VPC/private subnets** for databases, caches, and internal services. No direct internet exposure.
- Apply account-level **guardrails** (AWS SCPs, Azure Policy, GCP Org Policies) to prevent dangerous actions.

## Logging & Error Handling

- Log **security events**: authentication attempts, authorization failures, input validation failures, privilege changes.
- **Never log secrets**, tokens, passwords, or full credit card numbers.
- Return **generic error messages** to clients. Log detailed errors server-side only.
- Set **alerting** on: repeated auth failures, privilege escalation, anomalous access patterns, new admin accounts.

## LLM/AI Application Security

- Treat all **LLM output as untrusted** — validate, sanitize, and escape before using in SQL, HTML, shell, or file operations.
- **Never embed secrets** in system prompts — they are extractable.
- Apply **strict input/output guards** — maximum token limits, content filters, format validation on model responses.
- Enforce **least privilege for AI agents** — explicit allowlists of permitted tools/actions, require human approval for destructive operations.
- Validate all **RAG sources** for integrity. Sanitize retrieved content before injection into prompts.

## Mobile Security (Android/iOS)

- Store secrets in **platform keystore** (Android Keystore / iOS Keychain). Never in SharedPreferences, UserDefaults, or local databases.
- Enforce **TLS everywhere** with proper certificate validation. Implement **certificate pinning** for critical connections.
- Set `android:debuggable="false"`, `android:allowBackup="false"`, `android:exported="false"` (unless needed).
- Validate **deep links and IPC** inputs. Never trust data from intents or URL schemes.
- Request **minimum permissions**. Use runtime permissions and justify each one.

## Secure by Design Principles

- **Ship secure by default** — Every feature launches with the most secure usable configuration. Customers should not need a hardening guide.
- **No default passwords or admin accounts** — Force unique credential creation during initial setup.
- **Enable MFA by default** — MFA must be available at no extra cost, enforced for admins, and strongly prompted for all users.
- **Enable logging by default** — Security events (auth, authz, config changes) must be logged out of the box, not as a paid add-on.
- **Eliminate entire vulnerability classes** — Prefer memory-safe languages, parameterized queries, auto-escaping frameworks, and type-safe deserialization over patching individual bugs.
- **Publish `security.txt`** — Every web application should have `/.well-known/security.txt` with contact, VDP link, and encryption key.
- **Generate SBOM** — Every release must produce a Software Bill of Materials (CycloneDX or SPDX).
- **Define remediation SLAs** — Critical ≤ 7 days, High ≤ 30 days, Medium ≤ 90 days. Track compliance.

---

## Security Review Workflow

When asked to perform a security review, audit, or scan of code for vulnerabilities, follow this structured four-phase workflow. The goal is **precision over volume** — every finding must be confirmed reachable and non-trivially exploitable before it is reported as a real vulnerability.

---

### Phase 0 — Context Discovery

Before analyzing any code, establish the application context. This affects severity, reachability, and what counts as a false positive.

1. **Project type and attack surface** — Web app, API, CLI, library, mobile app, serverless function? Which interfaces are exposed to untrusted input?
2. **Technology stack and versions** — Detect language runtimes, frameworks, and library versions from `package.json`, `requirements.txt`, `go.mod`, `pom.xml`, `Gemfile`, `Cargo.toml`, `composer.json`, etc. Versions determine which CVEs apply.
3. **Existing security controls** — Identify authentication middleware, input validation layers, ORM usage, sanitization helpers, and security headers already present. These affect exploitability.
4. **Trust boundaries** — Map what data crosses a trust boundary: HTTP requests, file uploads, query parameters, environment variables, database results, IPC/RPC calls, queue messages, WebSocket payloads.

Summarize the detected context in a brief paragraph before the findings table.

---

### Phase 1 — Analysis Methodology

Apply all four techniques during code review. A finding advances to the findings table only after passing through this filter.

#### Taint Analysis
Trace data flow from **sources** to **sinks** without adequate sanitization:
- **Sources:** HTTP params/body/headers/cookies, URL path segments, file uploads, `process.env`, database results, external API responses, WebSocket messages, deserialized objects.
- **Sinks:** SQL builders, shell execution functions, `eval`/`exec`/`new Function`, file path operations, HTML rendering, redirect targets, deserialization functions, log statements (for sensitive data).
- A vulnerability is **confirmed** only when an unbroken taint path exists from a source to a sink with no sufficient validation, sanitization, or encoding in between. If the path is broken by a validated allowlist, parameterized query, or safe API, mark as false positive.

#### Reachability Analysis
Assess whether the vulnerable code path is reachable from an exposed attack surface:
- Is the function called from an exposed endpoint, route, or public API?
- Is the path behind authentication/authorization? (Reduces severity — exploitable only by authenticated users.)
- Is the vulnerable branch reachable with realistic inputs, or only under impossible preconditions?
- Downgrade unreachable findings to ⚪ **Info** or mark as false positive rather than reporting them at face value.

#### Dependency Classification
For findings involving third-party packages:
- **Direct** — explicitly listed in the project manifest; the project imports and calls it. Full severity applies if the vulnerable API is used.
- **Transitive** — pulled in by another dependency; not directly imported by the project. Assess whether the vulnerable function/API is actually invoked via the dependency chain in a way that affects this project. If not exercised, downgrade to ⚪ **Info** or mark as false positive.
- Always note the dependency depth (e.g., `express → qs@6.5.2` for a transitive dep).

#### Attack Path Analysis
For Critical and High findings, assess the worst-case exploitation scenario:
- What is the maximum impact if exploited? (RCE, auth bypass, data exfiltration, SSRF to internal network, privilege escalation, denial of service.)
- Does exploitation require chaining with another vulnerability? If so, describe the chain.
- Does exploitation require authenticated access, specific timing, or privileged position? These factors affect real-world risk.
- Document the attack path briefly when it justifies the severity rating or explains why a finding is lower-risk than it appears.

---

### Phase 2 — Findings Table

Present all confirmed and suspected findings sorted by severity (Critical → High → Medium → Low → Informational). Include false positives in the table — mark them explicitly so the user can make the final call.

| # | Severity | Vulnerability | Location | Reachable | Dep Type | False Positive? | Recommendation |
|---|----------|--------------|----------|-----------|----------|-----------------|----------------|
| 1 | 🔴 Critical | SQL Injection | `db.js:42` | Yes — `POST /login` (unauthenticated) | N/A | No | Use parameterized queries |
| 2 | 🟠 High | CVE-2025-13465 Prototype Pollution | `package.json` (lodash 4.17.21) | Unknown — `mergeWith()` not called directly | Transitive via `express-utils` | Yes — vulnerable API not used | No action needed |
| 3 | 🟡 Medium | Weak PRNG (`Math.random`) | `token.js:8` | Yes — token used as session ID | N/A | No | Replace with `crypto.randomBytes(32)` |
| 4 | 🔵 Low | Missing `X-Content-Type-Options` | `app.js:3` | N/A — headers | N/A | Yes — set by upstream nginx | No action needed |
| 5 | ⚪ Info | `lodash@4.17.20` outdated | `package.json` | N/A | Direct | No | `npm update lodash` |

**Severity:**
- 🔴 **Critical** — exploitable without prerequisites; direct, severe impact (RCE, auth bypass, full data breach)
- 🟠 **High** — significant exploitable risk; may require some conditions
- 🟡 **Medium** — real issue with mitigating factors, auth requirement, or limited blast radius
- 🔵 **Low** — minor risk or defense-in-depth gap
- ⚪ **Info** — best practice gap, outdated dependency, or observation with no immediate exploitability

**Reachable values:** `Yes — [call path]` | `Auth-only` | `No — [reason]` | `Unknown` | `N/A`
**Dep Type values:** `Direct` | `Transitive via [pkg]` | `N/A`

If no vulnerabilities are found, state explicitly: "No security issues found. The code follows secure coding practices for the patterns reviewed."

---

### Phase 3 — Ask Which to Fix

After the table, always ask:

> "Which vulnerabilities would you like me to fix? You can say: a number or list (e.g. `1, 3`), `all`, `critical only`, `critical and high`, or `none` to skip."

Do not proceed with fixes until the user responds.

---

### Phase 4 — Fix and Status Table

After applying the requested fixes, present a status table covering every finding from Phase 2:

| # | Severity | Vulnerability | Status | How It Was Fixed |
|---|----------|--------------|--------|-----------------|
| 1 | 🔴 Critical | SQL Injection | ✅ Fixed | Replaced string concat with `?` placeholder; query now uses `db.query(sql, [username, password])` |
| 2 | 🟠 High | CVE-2025-13465 | ⏭️ Skipped | False positive — `mergeWith()` not called by this project |
| 3 | 🟡 Medium | Weak PRNG | ✅ Fixed | Replaced `Math.random()` with `crypto.randomBytes(32).toString('hex')` in `token.js:8` |
| 4 | 🔵 Low | Missing header | ⏭️ Skipped | False positive — set by upstream nginx |
| 5 | ⚪ Info | lodash outdated | ⏳ Pending | — |

**Status:** ✅ Fixed | ⏳ Pending (not yet selected) | ⏭️ Skipped (user choice or confirmed false positive)

---

> **Need detailed examples, audit checklists, or in-depth guidance?** Invoke the full security skill files — they contain comprehensive code examples, cross-reference tables, and framework-specific rules for each domain above. For architecture and design reviews, start with `code-security-secure-by-design.md`.
