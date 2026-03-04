# 🛡️ Code Security Rules — OWASP ASVS 5.0

> **Version:** 1.0.0
> **Based on:** [OWASP Application Security Verification Standard 5.0.0](https://owasp.org/www-project-application-security-verification-standard/) (May 2025)
> **Last updated:** February 2026
> **Usage:** Place this file in `.claude/rules/` in your repository.

---

## ⚙️ Configuration — Choose Your Target Level

**Set your target ASVS level below. Change the value to `1`, `2`, or `3`.**

```
TARGET_LEVEL: 2
```

### Level Definitions

| Level  | Name                   | For                                                   | Includes     |
| ------ | ---------------------- | ----------------------------------------------------- | ------------ |
| **L1** | Baseline               | All applications. Quick adoption, essential controls. | L1 only      |
| **L2** | Standard (recommended) | Most applications handling sensitive data.            | L1 + L2      |
| **L3** | High Assurance         | Critical apps: medical, financial, safety, military.  | L1 + L2 + L3 |

### How to Apply

- Rules marked `[L1]` apply to **all** levels.
- Rules marked `[L2]` apply when TARGET_LEVEL is **2 or 3**.
- Rules marked `[L3]` apply only when TARGET_LEVEL is **3**.
- **Levels are cumulative**: L2 includes all L1 rules; L3 includes all L1 + L2 rules.

When generating, reviewing, or refactoring code, **apply all rules up to and including the configured TARGET_LEVEL**. Each rule references its ASVS requirement ID (e.g., `v5.0.0-6.2.1`) for traceability.

---

## V1 — Encoding and Sanitization

Prevent injection attacks by encoding output and sanitizing input for each context.

### Injection Prevention

- `[L1]` **Context-aware output encoding** — Encode output relevant to the rendering context: HTML elements, attributes, CSS, URL parameters, HTTP headers. (`1.2.1`, `1.2.2`, `1.2.3`)
- `[L1]` **Parameterized queries** — Use parameterized queries, ORMs, or prepared statements for all database operations (SQL, NoSQL, HQL, Cypher). Never concatenate user input into queries. (`1.2.4`)
- `[L1]` **OS command injection prevention** — Use parameterized OS queries or contextual escaping for system calls. Never pass unvalidated user input to shell commands. (`1.2.5`)
- `[L2]` **LDAP, XPath, template, JNDI, mail injection** — Sanitize input before passing to LDAP, XPath, template engines, JNDI, mail systems, LaTeX processors, and memcache. Use allowlists where possible. (`1.2.6`–`1.2.9`, `1.3.5`–`1.3.11`)
- `[L3]` **CSV/formula injection** — Escape special characters (`=`, `+`, `-`, `@`, tab, null) at the start of CSV field values. Prevent ReDoS by avoiding exponential backtracking patterns. (`1.2.10`, `1.3.12`)

### Sanitization Fundamentals

- `[L1]` **HTML sanitization** — Sanitize all untrusted HTML (WYSIWYG editors) using a well-known sanitization library. (`1.3.1`)
- `[L1]` **No eval()** — Avoid `eval()` and dynamic code execution. If unavoidable, sanitize all input before execution. (`1.3.2`)
- `[L1]` **XXE prevention** — Configure XML parsers to use restrictive settings with external entity resolution disabled. (`1.5.1`)
- `[L2]` **Canonical decoding** — Decode input only once, before validation/sanitization, not after. (`1.1.1`)
- `[L2]` **SSRF prevention** — Validate untrusted URLs/data against an allowlist of protocols, domains, paths, and ports before making requests. (`1.3.6`)
- `[L2]` **Safe deserialization** — Use allowlists of object types or restrict client-defined types. Never use mechanisms marked as insecure with untrusted input. (`1.5.2`)

### Memory Safety (L2+)

- `[L2]` **Buffer, stack, heap overflow prevention** — Use memory-safe string operations, bounds checking, and safe pointer arithmetic. Validate integer ranges to prevent overflows. Release dynamically allocated memory properly. (`1.4.1`–`1.4.3`)

### Example

```python
# ❌ INSECURE — SQL concatenation
query = f"SELECT * FROM users WHERE email = '{email}'"

# ✅ SECURE — parameterized query (L1 requirement v5.0.0-1.2.4)
query = "SELECT * FROM users WHERE email = %s"
cursor.execute(query, (email,))
```

```python
# ❌ INSECURE — OS command injection
os.system(f"convert {user_filename} output.png")

# ✅ SECURE — parameterized subprocess (L1 requirement v5.0.0-1.2.5)
import subprocess
subprocess.run(["convert", user_filename, "output.png"], check=True)
```

---

## V2 — Validation and Business Logic

Validate all input and protect business flows against abuse.

- `[L1]` **Positive input validation** — Validate input against expected structure, types, lengths, and ranges using allowlists. For L1, focus on security-critical input; for L2+, apply to all input. (`2.2.1`)
- `[L1]` **Server-side validation** — Never rely on client-side validation as a security control. Enforce at a trusted service layer. (`2.2.2`)
- `[L1]` **Sequential business logic** — Enforce that business flows execute in the expected step order without skipping steps. (`2.3.1`)
- `[L2]` **Business limits** — Implement documented limits per user, per resource, and globally to prevent abuse. Use transactions with rollback for business operations. Prevent double-booking of limited resources. (`2.3.2`–`2.3.4`)
- `[L2]` **Anti-automation** — Protect functions against excessive automated calls that could lead to data exfiltration, resource exhaustion, or denial of service. (`2.4.1`)
- `[L3]` **Multi-user approval** — Require multi-user approval for high-value operations (large transfers, contract approvals, safety overrides). Enforce realistic human timing to prevent rapid automated submissions. (`2.3.5`, `2.4.2`)

### Example

```python
# ✅ SECURE — server-side validation with business limits (L1 + L2)
from pydantic import BaseModel, Field

class TransferRequest(BaseModel):
    amount: float = Field(gt=0, le=50000)  # Business limit
    to_account: str = Field(pattern=r"^\d{10,12}$")

@app.post("/api/transfer")
@require_auth
@rate_limit("5/minute")  # Anti-automation (L2)
def transfer(req: TransferRequest):
    if req.amount > 10000:
        require_mfa(current_user)  # Step-up for high value (L3)
    ...
```

---

## V3 — Web Frontend Security

Protect the browser-side of the application from XSS, CSRF, clickjacking, and other client-side attacks.

### Content & Rendering

- `[L1]` **Prevent unintended content interpretation** — Use security controls (Sec-Fetch-\* validation, CSP sandbox, Content-Disposition: attachment) to prevent browsers from rendering uploaded files or API responses in wrong contexts. (`3.2.1`)
- `[L1]` **Safe text rendering** — Use `createTextNode()` or `textContent` instead of `innerHTML` when displaying text content, to prevent XSS. (`3.2.2`)

### Cookies

- `[L1]` **Secure attribute** — Set `Secure` attribute on all cookies. Use `__Secure-` or `__Host-` prefix. (`3.3.1`)
- `[L2]` **SameSite, HttpOnly, \_\_Host- prefix** — Set `SameSite` according to cookie purpose. Use `HttpOnly` for session tokens. Use `__Host-` prefix unless cross-host sharing is needed. (`3.3.2`–`3.3.4`)

### Security Headers

- `[L1]` **HSTS** — Include `Strict-Transport-Security` with `max-age` ≥ 1 year on all responses. For L2+, include subdomains. (`3.4.1`)
- `[L1]` **CORS** — Use fixed `Access-Control-Allow-Origin` values or validate Origin against an allowlist. Never use `*` with sensitive data. (`3.4.2`)
- `[L2]` **Content-Security-Policy** — Define CSP with at minimum `object-src 'none'` and `base-uri 'none'`. Use allowlists or nonces/hashes. For L3, require per-response nonces. (`3.4.3`)
- `[L2]` **X-Content-Type-Options, Referrer-Policy, frame-ancestors** — Set `nosniff`, configure Referrer-Policy to prevent sensitive URL leakage, and use CSP `frame-ancestors` instead of X-Frame-Options. (`3.4.4`–`3.4.6`)

### CSRF Protection

- `[L1]` **Anti-CSRF controls** — If not relying on CORS preflight, use anti-forgery tokens or custom headers. Ensure sensitive operations use POST/PUT/PATCH/DELETE, not GET. Validate Sec-Fetch-\* headers. (`3.5.1`–`3.5.3`)

### Example

```python
# ✅ SECURE — security headers middleware (covering L1 + L2)
@app.after_request
def security_headers(response):
    response.headers["Strict-Transport-Security"] = "max-age=63072000; includeSubDomains"
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; object-src 'none'; base-uri 'none'; "
        "frame-ancestors 'none'; script-src 'self'"
    )
    return response
```

---

## V4 — API and Web Service

Secure APIs, HTTP communication, GraphQL, and WebSocket connections.

- `[L1]` **Content-Type matching** — Every HTTP response with a body must have a correct Content-Type with charset (e.g., `UTF-8`). (`4.1.1`)
- `[L1]` **WSS for WebSocket** — Use TLS for all WebSocket connections (WSS, not WS). (`4.4.1`)
- `[L2]` **No transparent HTTP→HTTPS redirect for APIs** — Only redirect user-facing browser endpoints. API endpoints receiving unencrypted requests must fail, not silently redirect. (`4.1.2`)
- `[L2]` **Prevent header override** — Ensure headers set by intermediaries (X-Real-IP, X-Forwarded-\*) cannot be overridden by end users. (`4.1.3`)
- `[L2]` **GraphQL depth/cost limiting** — Use query allowlists, depth limiting, or cost analysis to prevent DoS from nested queries. Disable introspection in production. (`4.3.1`, `4.3.2`)
- `[L2]` **HTTP request smuggling** — Ensure all components (LBs, firewalls, servers) use consistent HTTP message boundary detection. (`4.2.1`)

---

## V5 — File Handling

Secure file upload, storage, and download operations.

- `[L1]` **File size limits** — Only accept files of a size the application can process without DoS. (`5.2.1`)
- `[L1]` **File type validation** — Validate file extension AND content (magic bytes). For L1, focus on security-critical files; for L2+, apply to all. (`5.2.2`)
- `[L1]` **No server-side execution** — Uploaded files stored in public folders must not be executable as server-side code. (`5.3.1`)
- `[L1]` **Path traversal prevention** — Use internally generated file paths. If user filenames are used, strictly validate and sanitize to prevent LFI, RFI, SSRF. (`5.3.2`)
- `[L2]` **Archive validation** — Check compressed files against max uncompressed size and max file count before extraction. Validate/ignore filenames in downloads. (`5.2.3`, `5.4.1`, `5.4.2`)
- `[L2]` **Antivirus scanning** — Scan files from untrusted sources. (`5.4.3`)

### Example

```python
# ✅ SECURE — file upload validation (L1 requirements)
import magic

ALLOWED_TYPES = {"image/jpeg", "image/png", "image/webp"}
MAX_SIZE = 5 * 1024 * 1024  # 5MB

@app.post("/api/upload")
@require_auth
def upload(file: UploadFile):
    if file.size > MAX_SIZE:
        raise HTTPException(413, "File too large")
    mime = magic.from_buffer(file.file.read(2048), mime=True)
    file.file.seek(0)
    if mime not in ALLOWED_TYPES:
        raise HTTPException(415, "Unsupported file type")
    safe_name = uuid4().hex + mimetypes.guess_extension(mime)
    save_path = UPLOAD_DIR / safe_name  # Internally generated path
    ...
```

---

## V6 — Authentication

Implement robust authentication aligned with NIST 800-63B.

### Password Security

- `[L1]` **Minimum 8 characters** (15+ recommended). No composition rules (uppercase/special required). No periodic rotation. Allow paste and password managers. Verify password exactly as received (no truncation). (`6.2.1`–`6.2.8`)
- `[L1]` **Block common passwords** — Check against at least top 3000 breached passwords matching the policy. (`6.2.4`)
- `[L2]` **Allow 64+ characters**. Check against breached password databases. Use context-specific word blocklist. No forced rotation unless compromised. (`6.2.9`–`6.2.12`)

### General Authentication

- `[L1]` **Anti-brute-force** — Implement rate limiting, anti-automation, and adaptive controls per documentation. (`6.3.1`)
- `[L1]` **No default accounts** — Remove or disable default credentials (root, admin, sa). (`6.3.2`)
- `[L1]` **Secure initial passwords** — System-generated passwords must be random, follow policy, and expire after first use or short period. No password hints or secret questions. (`6.4.1`, `6.4.2`)
- `[L2]` **Multi-factor authentication** — MFA required for access. For L3, one factor must be hardware-based (FIDO key) with phishing resistance. (`6.3.3`)
- `[L2]` **Consistent auth pathways** — All authentication pathways must enforce the same security controls. (`6.3.4`)
- `[L2]` **Secure password reset** — Reset process must not bypass MFA. If MFA factor is lost, require identity proofing at enrollment level. (`6.4.3`, `6.4.4`)

### MFA Specifics (L2+)

- `[L2]` **One-time use** — OTPs, lookup secrets, and out-of-band codes usable only once. Generated with CSPRNG, minimum 20 bits entropy. Short lifetime (10min out-of-band, 30s TOTP). (`6.5.1`–`6.5.5`)
- `[L2]` **SMS/phone OTP caution** — Only offer if phone validated and stronger alternatives also available. For L3, SMS/phone must not be an option. (`6.6.1`)

### Identity Provider Integration (L2+)

- `[L2]` **Validate IdP assertions** — Verify digital signatures on JWTs/SAML. Prevent cross-IdP spoofing. Process SAML assertions only once. Validate authentication strength claims (acr, amr). (`6.8.1`–`6.8.4`)

### Example

```python
# ✅ SECURE — password validation (L1 + L2)
from argon2 import PasswordHasher

ph = PasswordHasher(time_cost=3, memory_cost=65536, parallelism=4)

def validate_new_password(password: str) -> bool:
    if len(password) < 8:                    # L1: min 8 chars
        raise ValueError("Password too short")
    if len(password) > 64:                   # L2: allow up to 64+
        pass  # Still valid
    if is_common_password(password):          # L1: check top 3000
        raise ValueError("Password too common")
    if is_breached(password):                 # L2: check breached DB
        raise ValueError("Password found in breach")
    if is_context_word(password):             # L2: context blocklist
        raise ValueError("Password too guessable")
    return True
```

---

## V7 — Session Management

Manage sessions securely with proper lifecycle controls.

- `[L1]` **Backend token verification** — Verify all session tokens at a trusted backend service. (`7.2.1`)
- `[L1]` **Dynamic tokens** — Use dynamically generated session tokens (not static API keys). Generate with CSPRNG, minimum 128 bits entropy. (`7.2.2`, `7.2.3`)
- `[L1]` **New token on authentication** — Generate new session token on login and re-authentication. Terminate the previous token. (`7.2.4`)
- `[L1]` **Proper session termination** — On logout/expiration, invalidate the session server-side. For self-contained tokens, maintain a revocation list or per-user signing key rotation. Terminate all sessions on account disable/delete. (`7.4.1`, `7.4.2`)
- `[L2]` **Inactivity and absolute timeout** — Enforce documented inactivity timeout and absolute max session lifetime. (`7.3.1`, `7.3.2`)
- `[L2]` **Terminate sessions on auth change** — Offer to terminate all sessions after password change, MFA update, or credential reset. Provide admin ability to terminate sessions. (`7.4.3`–`7.4.5`)
- `[L2]` **Re-authentication for sensitive changes** — Require full re-auth before modifying email, phone, MFA config, or other recovery info. (`7.5.1`)

---

## V8 — Authorization

Enforce access control at function, data, and field levels.

- `[L1]` **Function-level authorization** — Restrict function access to consumers with explicit permissions. Enforce at a trusted service layer, not client-side. (`8.2.1`, `8.3.1`)
- `[L1]` **Data-specific authorization (IDOR/BOLA)** — Verify each request accesses only objects the consumer has explicit permission for. (`8.2.2`)
- `[L2]` **Field-level authorization (BOPLA)** — Control which fields consumers can read/write. Prevent mass assignment. (`8.2.3`)
- `[L2]` **Multi-tenant isolation** — Use cross-tenant controls to ensure operations never affect unauthorized tenants. (`8.4.1`)
- `[L3]` **Contextual authorization** — Implement adaptive controls based on time, location, IP, device for auth decisions. Apply immediately when authorization state changes. (`8.2.4`, `8.3.2`)

### Example

```python
# ✅ SECURE — function + data + field authorization (L1 + L2)
@app.get("/api/orders/{order_id}")
@require_auth
@require_permission("orders:read")           # L1: function-level
def get_order(order_id: str):
    order = Order.query.filter_by(
        id=order_id,
        tenant_id=current_user.tenant_id,    # L2: tenant isolation
        user_id=current_user.id              # L1: data-specific (BOLA)
    ).first_or_404()
    return OrderReadSchema.from_orm(order)   # L2: field-level filtering
```

---

## V9 — Self-contained Tokens (JWT)

Secure creation, validation, and usage of self-contained tokens.

- `[L1]` **Validate signatures** — Always verify digital signature or MAC before accepting token contents. (`9.1.1`)
- `[L1]` **Algorithm allowlist** — Only permit explicitly allowed algorithms. Never allow `none`. Don't mix symmetric/asymmetric without controls against key confusion. (`9.1.2`)
- `[L1]` **Trusted key sources** — Validate keys against pre-configured trusted sources. Don't allow attackers to specify untrusted key sources via `jku`, `x5u`, or `jwk` headers. (`9.1.3`)
- `[L1]` **Validate time span** — Verify `nbf` and `exp` claims against current time. (`9.2.1`)
- `[L2]` **Token type and audience** — Validate token type (access vs ID) and audience (`aud`) claim against service allowlist. Enforce unique audience identifiers when issuer uses same key for multiple audiences. (`9.2.2`–`9.2.4`)

### Example

```python
# ✅ SECURE — JWT validation (L1 requirements)
import jwt

def validate_token(token: str) -> dict:
    return jwt.decode(
        token,
        key=PUBLIC_KEY,
        algorithms=["RS256"],                     # Algorithm allowlist
        audience="https://api.myapp.com",          # Audience validation
        issuer="https://auth.myapp.com",           # Trusted issuer
        options={"require": ["exp", "iss", "aud", "sub"]},
    )
```

---

## V10 — OAuth and OIDC

Secure OAuth 2.0 and OpenID Connect flows.

### Authorization Server

- `[L1]` **Exact redirect URI matching** — Validate redirect URIs against pre-registered allowlist using exact string comparison. (`10.4.1`)
- `[L1]` **One-time authorization codes** — Auth codes usable once only. If reused, revoke all related tokens. Max lifetime: 10min (L1/L2), 1min (L3). (`10.4.2`, `10.4.3`)
- `[L1]` **No Implicit or ROPC flows** — Only allow grants the client needs. `token` and `password` grants must not be used. (`10.4.4`)
- `[L1]` **Refresh token replay protection** — Use sender-constrained tokens (DPoP/mTLS), or at minimum refresh token rotation with revocation on reuse. (`10.4.5`)
- `[L2]` **PKCE required** — Require proof key for code exchange. Don't accept `plain` challenge method. (`10.4.6`)
- `[L2]` **Refresh token expiration and revocation** — Absolute expiration on refresh tokens. User-accessible revocation UI. Authenticate confidential clients on all backchannel requests. (`10.4.8`–`10.4.10`)

### Client

- `[L2]` **CSRF/mix-up protection** — Use PKCE or state parameter. Defend against IdP mix-up when using multiple providers. Validate nonce in ID Token. Validate audience. (`10.2.1`, `10.2.2`, `10.5.1`–`10.5.4`)
- `[L2]` **Consent management** — Require explicit user consent with clear information. Allow review and revocation. (`10.7.1`–`10.7.3`)

### Resource Server

- `[L2]` **Validate audience, scope, and subject** — Accept only tokens intended for this service. Enforce delegated authorization from scope/authorization_details. Identify users by `iss` + `sub` (not reassignable). (`10.3.1`–`10.3.3`)

---

## V11 — Cryptography

Use strong, modern cryptographic primitives.

- `[L1]` **No insecure modes or padding** — No ECB mode, no PKCS#1 v1.5 padding. Use AES-GCM or other approved authenticated encryption. (`11.3.1`, `11.3.2`)
- `[L1]` **Approved hash functions** — No MD5 or SHA-1 for any cryptographic purpose. Use SHA-256+ for hashing. (`11.4.1`)
- `[L2]` **Password hashing** — Use approved KDF (Argon2id, bcrypt, scrypt, PBKDF2 with HMAC-SHA-256) with parameters tuned for ~250ms. (`11.4.2`)
- `[L2]` **Minimum 128-bit security** — All cryptographic primitives must provide at least 128-bit security (e.g., AES-256, ECC P-256, RSA-3072+). (`11.2.3`)
- `[L2]` **CSPRNG** — All random values intended to be non-guessable must use CSPRNG with ≥128 bits entropy. Standard UUIDs don't meet this requirement. (`11.5.1`)
- `[L2]` **Crypto agility** — Design so algorithms, key lengths, and modes can be upgraded (including to post-quantum) without rewriting. (`11.2.2`)
- `[L2]` **Cryptographic inventory** — Document all keys, algorithms, certificates, where they're used, and lifecycle policies. (`11.1.1`, `11.1.2`)

---

## V12 — Secure Communication

Protect all data in transit.

- `[L1]` **TLS 1.2+ everywhere** — Enable only TLS 1.2 and 1.3 for all client-facing connections. Prefer TLS 1.3. (`12.1.1`)
- `[L1]` **HTTPS for all external services** — TLS for all HTTP connectivity. No fallback to unencrypted. Use publicly trusted certificates. (`12.2.1`, `12.2.2`)
- `[L2]` **Strong cipher suites** — Only recommended suites, strongest preferred. For L3, require forward secrecy only. (`12.1.2`)
- `[L2]` **TLS for internal communications** — Encrypt all inbound/outbound connections including to databases, monitoring, management tools. Validate TLS certificates. Use trusted internal CAs for self-signed certs. (`12.3.1`–`12.3.4`)
- `[L3]` **mTLS for internal services** — Use TLS client authentication between internal services with PKI. (`12.3.5`)

---

## V13 — Configuration

Secure server and application configuration, secret management, and information leakage prevention.

### Secret Management

- `[L2]` **Use a secrets vault** — Use a secrets management solution (key vault, HSM for L3) to create, store, control access, and destroy secrets. No secrets in source code or build artifacts. (`13.3.1`)
- `[L2]` **Least privilege for secrets** — Each service accesses only secrets it needs. (`13.3.2`)
- `[L2]` **Service authentication** — Backend components authenticate using individual service accounts, short-lived tokens, or certificates — not static passwords, API keys, or shared accounts. (`13.2.1`, `13.2.2`)
- `[L2]` **No default credentials** — Never use default credentials for service authentication. (`13.2.3`)
- `[L2]` **Outbound allowlists** — Define allowlists for external resources the application can communicate with. (`13.2.4`, `13.2.5`)

### Information Leakage

- `[L1]` **No source control metadata** — Deploy without `.git`/`.svn` folders or make them inaccessible. (`13.4.1`)
- `[L2]` **Disable debug in production** — No debug modes, no exposed directory listings, no TRACE method, no exposed internal documentation endpoints. (`13.4.2`–`13.4.5`)
- `[L3]` **No version disclosure** — Don't expose backend component version info. Serve only files with allowed extensions. (`13.4.6`, `13.4.7`)

---

## V14 — Data Protection

Protect sensitive data at rest and in transit.

- `[L1]` **No sensitive data in URLs** — Send sensitive data (API keys, session tokens) only in HTTP body or headers, never in query strings. (`14.2.1`)
- `[L1]` **Clear client storage on session end** — Clear authenticated data from browser DOM on logout/session termination. (`14.3.1`)
- `[L2]` **Classify and protect** — Identify and classify all sensitive data with documented protection levels. Implement encryption, integrity, retention, logging, and access controls per classification. (`14.1.1`, `14.1.2`, `14.2.4`)
- `[L2]` **No sensitive data caching** — Prevent caching of sensitive data in server components. Set `Cache-Control: no-store` for sensitive responses. Don't store sensitive data in browser storage (localStorage, sessionStorage, IndexedDB) except session tokens. (`14.2.2`, `14.3.2`, `14.3.3`)
- `[L2]` **No data leakage to third parties** — Don't send sensitive data to untrusted trackers or analytics. (`14.2.3`)

---

## V15 — Secure Coding and Architecture

Maintain secure dependencies, defensive coding, and safe concurrency.

### Dependencies

- `[L1]` **Timely updates** — Maintain documented remediation timeframes for vulnerable components. Keep all components within these timeframes. (`15.1.1`, `15.2.1`)
- `[L2]` **SBOM** — Maintain a software bill of materials. Verify components come from trusted repositories. (`15.1.2`)
- `[L2]` **No test code in production** — Production must only contain required functionality. (`15.2.3`)

### Defensive Coding

- `[L1]` **Return minimal data** — Only return the required subset of fields from data objects. (`15.3.1`)
- `[L2]` **Mass assignment protection** — Limit allowed fields per controller/action. Prevent inserting or updating unintended fields. (`15.3.3`)
- `[L2]` **Don't follow redirects** — When making backend HTTP calls, don't follow redirects unless explicitly intended. (`15.3.2`)
- `[L2]` **Type safety** — Explicitly ensure correct variable types with strict equality. Prevent prototype pollution in JavaScript (use Map/Set over object literals). Defend against HTTP parameter pollution. (`15.3.5`–`15.3.7`)

### Concurrency (L3)

- `[L3]` **Thread safety** — Use synchronization mechanisms for shared objects. Perform state checks and actions atomically to prevent TOCTOU. Implement fair resource allocation to prevent starvation. (`15.4.1`–`15.4.4`)

---

## V16 — Security Logging and Error Handling

Log security events, handle errors gracefully, and protect logs.

- `[L2]` **Structured logging** — Include who, what, when, where metadata in each entry. Synchronize time sources to UTC. Use a common format processable by log tools. (`16.2.1`–`16.2.4`)
- `[L2]` **Log security events** — Log all authentication events (success/failure), failed authorization, security control bypass attempts, and unexpected errors. (`16.3.1`–`16.3.4`)
- `[L2]` **Protect sensitive data in logs** — Enforce logging rules per data classification. Never log credentials or payment details. Hash/mask session tokens. (`16.2.5`)
- `[L2]` **Log integrity** — Encode log data to prevent injection. Protect logs from unauthorized access/modification. Transmit to a logically separate system. (`16.4.1`–`16.4.3`)
- `[L2]` **Secure error handling** — Return generic error messages to users (no stack traces, query details, keys). Fail securely (circuit breakers, fail-closed). Don't allow exceptions to cause fail-open conditions. (`16.5.1`–`16.5.3`)

---

## V17 — WebRTC (if applicable)

Secure real-time communication components.

- `[L2]` **TURN server security** — Block relay access to reserved IP ranges (internal networks, loopback) for both IPv4 and IPv6. Manage DTLS certificate keys per cryptographic policy. Use approved DTLS cipher suites and DTLS-SRTP profiles. Verify SRTP authentication. Handle malformed SRTP gracefully. Implement signaling rate limiting and input validation. (`17.1.1`, `17.2.1`–`17.2.4`, `17.3.1`, `17.3.2`)
- `[L3]` **Resource exhaustion prevention** — Protect TURN and media servers against flood attacks from legitimate users. Verify DTLS certificate against SDP fingerprint. (`17.1.2`, `17.2.5`–`17.2.8`)

---

## Quick Checklist for Code Review

| Chapter | Domain                | L1 Key Question                                              | L2 Addition                                   | L3 Addition                        |
| ------- | --------------------- | ------------------------------------------------------------ | --------------------------------------------- | ---------------------------------- |
| V1      | Encoding/Sanitization | Parameterized queries? Context-aware encoding? XXE disabled? | SSRF protection? Safe deserialization?        | CSV injection? Memory safety?      |
| V2      | Validation/Logic      | Server-side validation? Sequential flows?                    | Business limits? Anti-automation?             | Multi-user approval?               |
| V3      | Web Frontend          | HSTS? CORS? CSRF tokens? Secure cookies?                     | CSP? nosniff? Referrer-Policy?                | Per-response nonces? HSTS preload? |
| V4      | API/WebService        | Content-Type? WSS?                                           | GraphQL limits? No smuggling?                 | Per-message signatures?            |
| V5      | File Handling         | Size limits? Type validation? Path traversal?                | Archive validation? AV scan?                  | Quota per user? Pixel flood?       |
| V6      | Authentication        | Min 8 chars? Common pw check? No defaults?                   | MFA? Breach check? Secure reset?              | Hardware MFA? No SMS OTP?          |
| V7      | Session               | Dynamic tokens? 128-bit entropy? New on auth?                | Timeout? Re-auth for changes?                 | Step-up for sensitive ops?         |
| V8      | Authorization         | Function-level? Data-specific (BOLA)?                        | Field-level (BOPLA)? Multi-tenant?            | Contextual adaptive?               |
| V9      | Tokens (JWT)          | Signature? Algorithm allowlist? Time check?                  | Type/audience validation?                     | —                                  |
| V10     | OAuth/OIDC            | Exact redirect URI? One-time codes? No implicit?             | PKCE? Consent? Audience?                      | Sender-constrained? mTLS/DPoP?     |
| V11     | Cryptography          | No ECB/MD5? Approved ciphers?                                | Password KDF? 128-bit min? CSPRNG?            | PQC readiness? Constant-time?      |
| V12     | Communication         | TLS 1.2+? HTTPS everywhere?                                  | Internal TLS? Cert validation?                | mTLS between services?             |
| V13     | Configuration         | No .git exposed?                                             | Secrets vault? No defaults? Debug off?        | HSM? Version hiding?               |
| V14     | Data Protection       | No secrets in URLs? Clear on logout?                         | Classify data? No caching?                    | Data retention? Minimize exposure? |
| V15     | Secure Coding         | Updated deps? Minimal data return?                           | SBOM? Mass assignment? Type safety?           | Thread safety? TOCTOU?             |
| V16     | Logging/Errors        | —                                                            | Structured logs? Auth events? Generic errors? | Last-resort error handler?         |
| V17     | WebRTC                | —                                                            | TURN hardening? DTLS/SRTP? Rate limits?       | Flood resistance?                  |

---

## Level Selection Guide

| Criteria                 | L1                         | L2                                | L3                                                     |
| ------------------------ | -------------------------- | --------------------------------- | ------------------------------------------------------ |
| **Application type**     | Internal tools, low-risk   | Most production apps, B2B/B2C     | Banking, healthcare, military, critical infrastructure |
| **Data sensitivity**     | Public or low-sensitivity  | PII, financial, business-critical | Classified, medical records, payment processing        |
| **Regulatory**           | Minimal requirements       | GDPR, SOC 2, general compliance   | PCI-DSS, HIPAA, FedRAMP, ISO 27001 high                |
| **Testing**              | Automated + basic pen test | Source-assisted pen test          | Full code review + advanced testing                    |
| **Approx. requirements** | ~90                        | ~240 (L1+L2)                      | ~350 (L1+L2+L3)                                        |

---

## References

- [OWASP ASVS 5.0.0 — Official Page](https://owasp.org/www-project-application-security-verification-standard/)
- [OWASP ASVS 5.0.0 — GitHub](https://github.com/OWASP/ASVS/tree/v5.0.0)
- [OWASP ASVS 5.0.0 — PDF](https://github.com/OWASP/ASVS/raw/v5.0.0/5.0/OWASP_Application_Security_Verification_Standard_5.0.0_en.pdf)
- [OWASP ASVS 5.0.0 — CSV](https://github.com/OWASP/ASVS/raw/v5.0.0/5.0/docs_en/OWASP_Application_Security_Verification_Standard_5.0.0_en.csv)
- [OWASP Cheat Sheet Series — ASVS Index](https://cheatsheetseries.owasp.org/IndexASVS.html)
- [NIST SP 800-63B — Digital Identity Guidelines](https://pages.nist.gov/800-63-3/sp800-63b.html)

---

## License

This document is released under [CC BY-SA 4.0](https://creativecommons.org/licenses/by-sa/4.0/). Based on the work of the [OWASP Foundation](https://owasp.org/).
