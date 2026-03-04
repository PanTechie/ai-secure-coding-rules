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

> **Need detailed examples, audit checklists, or in-depth guidance?** Invoke the full security skill files — they contain comprehensive code examples, cross-reference tables, and framework-specific rules for each domain above. For architecture and design reviews, start with `code-security-secure-by-design.md`.
