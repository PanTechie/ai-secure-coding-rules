# 🔐 Code Security Rules — OWASP API Security Top 10:2023

> **Version:** 1.0.0
> **Based on:** [OWASP API Security Top 10:2023](https://owasp.org/API-Security/editions/2023/en/0x11-t10/)
> **Last updated:** February 2026
> **Usage:** Place this file in `.claude/rules/` in your repository.

---

## General Instructions

When generating, reviewing, or refactoring **API** code (REST, GraphQL, gRPC, WebSocket), **always apply the following security rules**. APIs expose business logic and sensitive data (PII, financial, health), making them a primary target for attackers.

This document complements `code-security-owasp-top10-2025.md` (focused on web applications) with risks **specific to APIs**.

---

## API1:2023 — Broken Object Level Authorization (BOLA)

Attackers manipulate object identifiers in requests to access other users' data. This is risk #1 because APIs naturally expose endpoints that receive IDs, creating a broad attack surface for object-level access control failures.

### Mandatory rules

- **Validate ownership on every operation** — Each endpoint that receives an object ID must verify whether the authenticated user has permission to access **that specific object**, not just whether they are authenticated.
- **Don't trust client-supplied IDs** — IDs sent via URL, body, or query params are user input and must be treated as untrusted.
- **Prefer non-sequential IDs** — Use UUIDs instead of auto-incrementing IDs to hinder enumeration. This does not replace authorization but adds a layer.
- **Centralize authorization logic** — Implement object access checks in a reusable layer (middleware, decorator, policy) instead of repeating `if` statements in each handler.
- **Test BOLA explicitly** — Create automated tests where User A tries to access User B's resources. This must fail with 403/404.
- **Use 404 instead of 403 when appropriate** — To prevent object enumeration, return 404 ("not found") when the user lacks access, instead of 403 ("forbidden") which confirms the resource exists.

### Example

```python
# ❌ INSECURE — any authenticated user can access any order
@app.route("/api/orders/<order_id>")
@require_auth
def get_order(order_id):
    order = Order.query.get_or_404(order_id)
    return jsonify(order.to_dict())

# ✅ SECURE — verifies object ownership
@app.route("/api/orders/<order_id>")
@require_auth
def get_order(order_id):
    order = Order.query.filter_by(
        id=order_id,
        user_id=current_user.id  # Filter by owner
    ).first()
    if not order:
        abort(404)  # 404 instead of 403 to prevent enumeration
    return jsonify(order.to_dict())
```

```javascript
// ✅ Reusable resource authorization middleware (Express)
function authorizeResource(model, ownerField = "userId") {
  return async (req, res, next) => {
    const resource = await model.findByPk(req.params.id);
    if (!resource || resource[ownerField] !== req.user.id) {
      return res.status(404).json({ error: "Resource not found" });
    }
    req.resource = resource;
    next();
  };
}

// Usage:
app.get("/api/orders/:id", authenticate, authorizeResource(Order), getOrder);
app.delete(
  "/api/orders/:id",
  authenticate,
  authorizeResource(Order),
  deleteOrder,
);
```

---

## API2:2023 — Broken Authentication

Weak authentication mechanisms allow attackers to impersonate other users. Includes token failures, credential issues, recovery flow weaknesses, and session management issues in APIs.

### Mandatory rules

- **Protect all authentication flows** — Login, registration, password reset, token refresh, and credential exchange are all attack targets and must have equivalent protections.
- **Implement rate limiting on auth endpoints** — Limit login attempts by IP and by account. Use exponential backoff after consecutive failures.
- **Validate tokens rigorously** — Verify signature, expiration (`exp`), issuer (`iss`), audience (`aud`), and never accept tokens without full validation. Use established libraries for JWT validation.
- **Use short-lived tokens** — Access tokens should expire in minutes (5-15min). Use refresh tokens with rotation for long sessions. Revoke refresh tokens on logout.
- **Don't expose credentials in URLs** — Tokens and API keys must never appear in query strings (which are logged by servers and proxies). Use headers (`Authorization: Bearer ...`).
- **Treat API keys as passwords** — API keys must have minimum scope, expiration, and be rotated regularly. Don't embed them in client-side code.
- **Implement MFA for sensitive operations** — Transfers, email/password changes, and administrative operations should require an additional factor.
- **Use generic responses** — Authentication endpoints must not reveal whether an email/username exists in the system.

### Example

```python
# ✅ Complete JWT validation
import jwt
from datetime import datetime, timezone

def validate_token(token: str) -> dict:
    try:
        payload = jwt.decode(
            token,
            key=PUBLIC_KEY,
            algorithms=["RS256"],          # Explicit algorithm (never "none")
            audience="https://api.myapp.com",
            issuer="https://auth.myapp.com",
            options={
                "require": ["exp", "iss", "aud", "sub"],
                "verify_exp": True,
                "verify_iss": True,
                "verify_aud": True,
            },
        )
        return payload
    except jwt.ExpiredSignatureError:
        abort(401, description="Token expired")
    except jwt.InvalidTokenError:
        abort(401, description="Invalid token")
```

```python
# ✅ Rate limiting on login endpoint
from flask_limiter import Limiter

limiter = Limiter(app, key_func=get_remote_address)

@app.route("/api/auth/login", methods=["POST"])
@limiter.limit("5 per minute")        # Per IP
@limiter.limit("10 per hour", key_func=lambda: request.json.get("email", ""))  # Per account
def login():
    ...
```

---

## API3:2023 — Broken Object Property Level Authorization (BOPLA)

Combines "Excessive Data Exposure" and "Mass Assignment" from OWASP 2019, focusing on the root cause: lack of authorization at the **property** level of objects. An API may protect access to the object but fail to control which fields the user can read or modify.

### Mandatory rules

- **Return only necessary fields** — Never return the complete database object. Use DTOs/serializers that explicitly define which fields are exposed for each context.
- **Protect against Mass Assignment** — Define allowlists of fields the user can modify. Never do `Model.update(**request.json)` directly.
- **Differentiate read-only and writable fields** — Fields like `id`, `created_at`, `role`, `is_admin` must never be modifiable by the user.
- **Apply validation schemas** — Validate request payloads against schemas (JSON Schema, Pydantic, Zod) that define allowed fields, types, and constraints.
- **Separate responses by context** — The "my profile" endpoint may return email, but the "public profile" endpoint should not. Use different serializers.
- **Filter sensitive fields in logs** — Fields like `password`, `ssn`, `credit_card` must not appear in logs, even at debug level.
- **Reject unknown fields** — Requests with fields that are not part of the schema should be rejected or the fields should be silently ignored (context-dependent).

### Example

```python
# ❌ INSECURE — returns everything and accepts everything
@app.route("/api/users/<user_id>", methods=["GET", "PATCH"])
@require_auth
def user_profile(user_id):
    user = User.query.get_or_404(user_id)
    if request.method == "PATCH":
        # Mass Assignment: user can send {"role": "admin"}
        user.update(**request.json)
        db.session.commit()
    # Excessive Data Exposure: returns password hash, role, internal data
    return jsonify(user.__dict__)

# ✅ SECURE — explicit DTOs for reading and writing
from pydantic import BaseModel, Field

class UserPublicResponse(BaseModel):
    id: str
    name: str
    avatar_url: str | None
    # Sensitive fields are NOT included

class UserSelfResponse(UserPublicResponse):
    email: str
    phone: str | None
    # Still excludes: password_hash, role, internal_flags

class UserUpdateRequest(BaseModel):
    name: str | None = Field(None, max_length=100)
    avatar_url: str | None = Field(None, max_length=500)
    phone: str | None = Field(None, pattern=r"^\+\d{10,15}$")
    # Forbidden fields (role, email, id) DO NOT exist in the schema

@app.route("/api/users/me", methods=["PATCH"])
@require_auth
def update_profile():
    data = UserUpdateRequest.model_validate(request.json)
    # Only schema fields are applied
    current_user.update(**data.model_dump(exclude_unset=True))
    db.session.commit()
    return jsonify(UserSelfResponse.model_validate(current_user).model_dump())
```

```typescript
// ✅ Zod schema for TypeScript validation
import { z } from "zod";

const UpdateProfileSchema = z
  .object({
    name: z.string().max(100).optional(),
    avatarUrl: z.string().url().optional(),
    phone: z
      .string()
      .regex(/^\+\d{10,15}$/)
      .optional(),
  })
  .strict(); // Rejects unknown fields

app.patch("/api/users/me", authenticate, async (req, res) => {
  const result = UpdateProfileSchema.safeParse(req.body);
  if (!result.success) {
    return res.status(400).json({ errors: result.error.flatten() });
  }
  await updateUser(req.user.id, result.data);
});
```

---

## API4:2023 — Unrestricted Resource Consumption

APIs that don't limit requests or data volume enable denial-of-service (DoS) attacks, increased operational costs, and resource exhaustion. Includes CPU, memory, bandwidth, storage, and pay-per-request service consumption (SMS, email, biometrics).

### Mandatory rules

- **Implement rate limiting** — Define limits per user, per IP, and per endpoint. Use algorithms like token bucket or sliding window.
- **Limit payload sizes** — Configure maximum limits for body (`Content-Length`), uploads, individual fields, and number of items in arrays.
- **Implement mandatory pagination** — Never return entire collections. Force pagination with maximum limits (`max_per_page=100`). Never allow `?limit=999999`.
- **Define timeouts** — Configure timeouts on all operations: database queries, external service calls, file processing.
- **Limit query complexity** — For GraphQL, limit query depth and complexity. For REST, limit relationship expansion.
- **Protect pay-per-use services** — SMS, email, biometrics, and other paid integrations must have independent rate limiting and per-user quotas.
- **Monitor and alert** — Configure alerts for anomalous resource consumption (request spikes, CPU, memory, API costs).
- **Implement quotas** — Define daily/monthly quotas per user or per API key for expensive operations.

### Example

```python
# ✅ Secure pagination with limits
from pydantic import BaseModel, Field

class PaginationParams(BaseModel):
    page: int = Field(default=1, ge=1, le=10000)
    per_page: int = Field(default=20, ge=1, le=100)  # Maximum 100

@app.route("/api/products")
@require_auth
def list_products():
    params = PaginationParams.model_validate(request.args)
    products = Product.query.paginate(
        page=params.page,
        per_page=params.per_page,
        max_per_page=100,  # Additional safeguard
        error_out=False,
    )
    return jsonify({
        "data": [p.to_dict() for p in products.items],
        "pagination": {
            "page": products.page,
            "per_page": products.per_page,
            "total": products.total,
            "pages": products.pages,
        },
    })
```

```python
# ✅ Upload size limit and timeout
from werkzeug.utils import secure_filename

app.config["MAX_CONTENT_LENGTH"] = 5 * 1024 * 1024  # 5MB maximum

@app.route("/api/upload", methods=["POST"])
@require_auth
@limiter.limit("10 per hour")  # Maximum 10 uploads/hour
def upload_file():
    file = request.files.get("file")
    if not file:
        abort(400)
    # Validate file type by magic bytes, not extension
    allowed_types = {"image/jpeg", "image/png", "image/webp"}
    if file.content_type not in allowed_types:
        abort(415, description="Unsupported media type")
    filename = secure_filename(file.filename)
    ...
```

```yaml
# ✅ Nginx rate limiting configuration
http {
limit_req_zone $binary_remote_addr zone=api_general:10m rate=30r/s;
limit_req_zone $binary_remote_addr zone=api_auth:10m rate=5r/m;

server {
location /api/ {
limit_req zone=api_general burst=50 nodelay;
client_max_body_size 5m;
proxy_read_timeout 30s;
proxy_connect_timeout 10s;
}
location /api/auth/ {
limit_req zone=api_auth burst=10 nodelay;
}
}
}
```

---

## API5:2023 — Broken Function Level Authorization (BFLA)

APIs frequently expose multiple functions (CRUD, admin, reports). Attackers enumerate endpoints and invoke privileged functions if there's no per-function/role permission verification.

### Mandatory rules

- **Deny access by default** — Every function/endpoint must require explicit authorization. If a role doesn't have assigned permission, access is denied.
- **Separate admin endpoints from user endpoints** — Use clear prefixes (`/api/admin/...`) and apply distinct authorization middleware for each group.
- **Verify role/permission on the server** — Never rely solely on the UI to hide functionality. Every operation must verify permissions server-side.
- **Avoid predictable endpoints** — Don't create patterns like `/api/users` (public) and `/api/admin/users` (admin) where the only difference is the prefix. Attackers will try the admin pattern.
- **Test horizontal and vertical escalation** — Test whether a regular user can access admin endpoints (vertical) and whether an admin of scope A can access scope B (horizontal).
- **Audit privileged operations** — Every execution of an administrative function must be logged with details of the actor, action, and target.

### Example

```python
# ✅ Permission-based authorization middleware
from functools import wraps

def require_permission(*permissions):
    def decorator(f):
        @wraps(f)
        def wrapper(*args, **kwargs):
            if not current_user.has_any_permission(*permissions):
                audit_log.warning(
                    "BFLA attempt",
                    user_id=current_user.id,
                    endpoint=request.endpoint,
                    required=permissions,
                )
                abort(404)  # 404 instead of 403 to avoid confirming existence
            return f(*args, **kwargs)
        return wrapper
    return decorator

@app.route("/api/users", methods=["GET"])
@require_auth
@require_permission("users:list")
def list_users():
    ...

@app.route("/api/users/<user_id>", methods=["DELETE"])
@require_auth
@require_permission("users:delete")
def delete_user(user_id):
    audit_log.info("User deleted", actor=current_user.id, target=user_id)
    ...
```

---

## API6:2023 — Unrestricted Access to Sensitive Business Flows

APIs that expose sensitive business flows (purchases, reservations, comments, registrations) without compensating for automated/excessive use that can harm the business. Unlike implementation bugs — this is a design flaw that doesn't consider abuse at scale.

### Mandatory rules

- **Identify sensitive flows** — Map which endpoints represent business actions that, if abused at volume, harm the business: purchases, reservations, account creation, voting, posting, coupon usage.
- **Implement anti-automation** — Use device fingerprinting, CAPTCHA, bot detection, and behavioral analysis on sensitive flows.
- **Apply business limits** — Limit action frequency by business logic: maximum purchases per hour, reservations per day, comments per minute.
- **Detect anomalous patterns** — Monitor and alert on patterns like: same IP making hundreds of purchases, mass account creation, catalog scraping.
- **Don't rely solely on rate limiting** — IP-based rate limiting is insufficient (attackers use rotating IPs). Combine with per-account limits, fingerprinting, and behavioral analysis.
- **Consider business impact** — For each sensitive flow, document: "What happens if a bot executes this action 10,000 times in an hour?"

### Example

```python
# ✅ Purchase flow protection with multiple layers
@app.route("/api/checkout", methods=["POST"])
@require_auth
@limiter.limit("5 per minute")  # Rate limit per IP
@verify_captcha                   # CAPTCHA for purchases
def checkout():
    user = current_user

    # Business limit: maximum purchases per period
    recent_purchases = Purchase.query.filter(
        Purchase.user_id == user.id,
        Purchase.created_at > datetime.utcnow() - timedelta(hours=1),
    ).count()

    if recent_purchases >= 10:
        audit_log.warning("Purchase rate exceeded", user_id=user.id, count=recent_purchases)
        return {"error": "Purchase limit exceeded. Please try again later."}, 429

    # Check device fingerprint (detect automation)
    fingerprint = request.headers.get("X-Device-Fingerprint")
    if is_known_bot_fingerprint(fingerprint):
        audit_log.warning("Bot detected at checkout", user_id=user.id)
        abort(403)

    # Process purchase...
    ...
```

---

## API7:2023 — Server Side Request Forgery (SSRF)

Occurs when the API fetches a remote resource based on a user-supplied URL without adequate validation. Allows attackers to make the application send requests to internal destinations, even those protected by firewall or VPN.

### Mandatory rules

- **Validate and sanitize all input URLs** — Never fetch/request user-supplied URLs without validation.
- **Use destination allowlists** — Explicitly define which domains/IPs the application can access. Reject everything not on the list.
- **Block internal addresses** — Reject requests to private ranges: `127.0.0.0/8`, `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`, `169.254.169.254` (cloud metadata), `::1`, `fd00::/8`.
- **Resolve DNS before validating** — Validate the IP **after** DNS resolution to prevent DNS rebinding (domain resolving to internal IP).
- **Don't trust schemas** — Block dangerous schemas like `file://`, `gopher://`, `dict://`. Allow only `https://`.
- **Disable redirects** — Or validate each redirect hop individually.
- **Isolate services that make external requests** — Run them in an isolated network with controlled egress.

### Example

```python
# ❌ INSECURE — SSRF via webhook URL
@app.route("/api/webhooks", methods=["POST"])
def create_webhook():
    url = request.json["callback_url"]
    # Direct request to user-supplied URL
    requests.get(url)  # Can access http://169.254.169.254/latest/meta-data/

# ✅ SECURE — complete URL validation
import ipaddress
import socket
from urllib.parse import urlparse

BLOCKED_NETWORKS = [
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("169.254.0.0/16"),  # Link-local + cloud metadata
    ipaddress.ip_network("::1/128"),
    ipaddress.ip_network("fd00::/8"),
]

ALLOWED_SCHEMES = {"https"}

def validate_url(url: str) -> bool:
    parsed = urlparse(url)
    if parsed.scheme not in ALLOWED_SCHEMES:
        return False
    try:
        resolved_ips = socket.getaddrinfo(parsed.hostname, parsed.port or 443)
        for _, _, _, _, addr in resolved_ips:
            ip = ipaddress.ip_address(addr[0])
            if any(ip in network for network in BLOCKED_NETWORKS):
                return False
    except socket.gaierror:
        return False
    return True

@app.route("/api/webhooks", methods=["POST"])
@require_auth
def create_webhook():
    url = request.json.get("callback_url", "")
    if not validate_url(url):
        abort(400, description="Invalid or disallowed URL")
    ...
```

---

## API8:2023 — Security Misconfiguration

APIs and their supporting systems have complex configurations. Configuration errors open the door to various attacks: permissive CORS, missing headers, debug enabled, weak TLS, excessive permissions.

### Mandatory rules

- **Automate security configuration** — Use Infrastructure as Code (Terraform, Helm, Ansible) with versioned and reviewed security templates.
- **Disable unnecessary HTTP methods** — If the endpoint only supports GET and POST, explicitly block OPTIONS, PUT, DELETE, TRACE, PATCH.
- **Configure CORS correctly** — Never use `Access-Control-Allow-Origin: *` on authenticated APIs. Specify exact origins. Don't reflect the request's `Origin` header.
- **Remove debug/documentation endpoints in production** — Swagger UI, GraphQL Playground, `/debug`, `/health` with sensitive data, profilers — disable in production or protect with authentication.
- **Enforce TLS on all communications** — Use TLS 1.2+ and redirect HTTP to HTTPS. Include HSTS.
- **Configure generic error messages** — Stack traces, table names, software versions, and internal paths must never reach the client in production.
- **Disable CORS credentials with wildcard** — `Access-Control-Allow-Credentials: true` with `Access-Control-Allow-Origin: *` is a critical flaw.
- **Audit response headers** — Remove headers that reveal internal information: `Server`, `X-Powered-By`, `X-AspNet-Version`.

### Example

```python
# ✅ Restrictive CORS configuration (Flask)
from flask_cors import CORS

CORS(app, resources={
    r"/api/*": {
        "origins": [
            "https://app.mycompany.com",
            "https://admin.mycompany.com",
        ],
        "methods": ["GET", "POST", "PUT", "DELETE"],
        "allow_headers": ["Authorization", "Content-Type"],
        "expose_headers": ["X-Request-Id"],
        "supports_credentials": True,
        "max_age": 3600,
    }
})

# Remove headers that reveal information
@app.after_request
def remove_server_headers(response):
    response.headers.pop("Server", None)
    response.headers.pop("X-Powered-By", None)
    return response
```

```yaml
# ✅ Security configuration checklist for deployment
security_config:
  tls:
    min_version: "1.2"
    hsts: true
    hsts_max_age: 63072000
  cors:
    allow_credentials: true
    allowed_origins: ["https://app.example.com"] # NEVER "*"
  headers:
    remove: ["Server", "X-Powered-By", "X-AspNet-Version"]
    add:
      X-Content-Type-Options: "nosniff"
      X-Frame-Options: "DENY"
      Content-Security-Policy: "default-src 'none'"
  debug:
    enabled: false # NEVER true in production
    swagger_ui: false # Disable in production
    stack_traces: false
  http_methods:
    global_allow: ["GET", "POST", "PUT", "DELETE", "PATCH"]
    global_deny: ["TRACE", "CONNECT"]
```

---

## API9:2023 — Improper Inventory Management

Undocumented or outdated APIs ("shadow APIs") and old versions still running create unknown attack surfaces. If you don't know an API exists, you can't protect it.

### Mandatory rules

- **Maintain a complete API inventory** — Document all endpoints, versions, environments (dev, staging, prod), and integrations. Use OpenAPI/Swagger as the source of truth.
- **Deprecate and remove old versions** — Define a lifecycle policy: maximum 2-3 active versions simultaneously. Deprecated versions must be shut down, not just ignored.
- **Don't expose internal APIs publicly** — Internal APIs must be on isolated networks. If accidentally exposed, they are easy targets.
- **Automate API discovery** — Use API discovery tools to identify undocumented endpoints in production.
- **Apply consistent security across all versions** — If a security fix is applied to v3, verify that v2 (still active) also received the fix.
- **Protect non-production environments** — Dev/staging environments frequently have weaker authentication and real data. Protect them or use synthetic data.
- **Document third-party integrations** — Maintain records of which external APIs your application consumes, with what permissions, and the risk if they are compromised.

### Example

```yaml
# ✅ Versioned API lifecycle policy
api_versioning:
  strategy: "url-prefix" # /api/v1/, /api/v2/
  active_versions:
    - version: "v3"
      status: "current"
      sunset: null
    - version: "v2"
      status: "deprecated"
      sunset: "2025-06-01" # Shutdown date
      deprecation_header: true # Sends Deprecation header
    # v1 was shut down on 2024-01-01

  rules:
    max_active_versions: 3
    sunset_notice_days: 180 # 6 months notice
    force_auth_all_versions: true
    security_patches_all_active: true
```

```python
# ✅ Automatic deprecation headers
@app.before_request
def add_deprecation_headers():
    if request.path.startswith("/api/v2/"):
        g.deprecated = True

@app.after_request
def deprecation_headers(response):
    if getattr(g, "deprecated", False):
        response.headers["Deprecation"] = "true"
        response.headers["Sunset"] = "Sat, 01 Jun 2025 00:00:00 GMT"
        response.headers["Link"] = '</api/v3/>; rel="successor-version"'
    return response
```

---

## API10:2023 — Unsafe Consumption of APIs

Developers tend to trust data from third-party APIs more than user input. But external APIs can be compromised, return malicious data, or behave unexpectedly. Every boundary is a trust boundary.

### Mandatory rules

- **Treat third-party API data as untrusted** — Validate, sanitize, and verify all data received from third parties, exactly as you would with user input.
- **Use HTTPS for all integrations** — Never consume external APIs via plain HTTP, even in "internal environments".
- **Validate response schemas** — Define expected schemas for external API responses and reject data that doesn't conform.
- **Implement timeouts and circuit breakers** — External APIs can become slow or unavailable. Set aggressive timeouts and fallbacks.
- **Limit received data** — Configure size limits for external API responses (body size, number of items).
- **Don't follow redirects blindly** — Validate each redirect destination from external APIs.
- **Isolate integrations** — Run external API calls in isolated processes/containers when possible.
- **Monitor integrations** — Alert on unexpected changes in third-party API behavior: new fields, format changes, anomalous latency.

### Example

```python
# ❌ INSECURE — blindly trusts third-party API
def get_exchange_rate(currency: str) -> float:
    response = requests.get(f"https://api.rates.example.com/latest/{currency}")
    data = response.json()
    # Uses value directly without validation
    return data["rate"]

# ✅ SECURE — validates third-party API response
import requests
from pydantic import BaseModel, field_validator
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

class ExchangeRateResponse(BaseModel):
    currency: str
    rate: float
    timestamp: str

    @field_validator("rate")
    @classmethod
    def rate_must_be_positive(cls, v):
        if v <= 0 or v > 1_000_000:
            raise ValueError(f"Exchange rate out of bounds: {v}")
        return v

# Session with timeout, retry, and size limit
session = requests.Session()
session.mount("https://", HTTPAdapter(
    max_retries=Retry(total=3, backoff_factor=0.5, status_forcelist=[502, 503, 504])
))

def get_exchange_rate(currency: str) -> float:
    try:
        response = session.get(
            f"https://api.rates.example.com/latest/{currency}",
            timeout=(5, 10),                       # (connect, read) timeout
            headers={"Accept": "application/json"},
            allow_redirects=False,                  # Don't follow redirects
        )
        response.raise_for_status()

        if len(response.content) > 10_240:         # Maximum 10KB
            raise ValueError("Response too large")

        data = ExchangeRateResponse.model_validate(response.json())
        return data.rate

    except (requests.RequestException, ValueError) as e:
        logger.error("Exchange rate API failed", error=str(e), currency=currency)
        # Safe fallback or raise — never return default value without warning
        raise ExternalServiceError(f"Exchange rate unavailable: {e}")
```

---

## Quick Checklist for API Code Review

Use this checklist when reviewing API code or Pull Requests:

| #     | Category                              | Key question                                                                                  |
| ----- | ------------------------------------- | --------------------------------------------------------------------------------------------- |
| API1  | Broken Object Level Authorization     | Does each endpoint verify the user can access **that specific object**?                       |
| API2  | Broken Authentication                 | Are tokens fully validated (signature, expiration, issuer, audience)?                         |
| API3  | Broken Object Property Level Auth     | Do responses use DTOs? Do requests validate only permitted fields (no mass assignment)?       |
| API4  | Unrestricted Resource Consumption     | Is there rate limiting, pagination with limits, and configured timeouts?                      |
| API5  | Broken Function Level Authorization   | Do admin/privileged functions verify role/permission on the server?                           |
| API6  | Unrestricted Sensitive Business Flows | Do sensitive flows (purchase, registration, voting) have anti-automation and business limits? |
| API7  | Server Side Request Forgery           | Are input URLs validated, internal IPs blocked, and destination allowlists in place?          |
| API8  | Security Misconfiguration             | Is CORS restrictive? Debug disabled? Sensitive headers removed?                               |
| API9  | Improper Inventory Management         | Are all APIs and versions documented? Have old versions been shut down?                       |
| API10 | Unsafe Consumption of APIs            | Is third-party API data validated with the same rigor as user input?                          |

---

## Recommended Design Patterns for Secure APIs

### Security middleware structure

```
Request → [Rate Limit] → [Auth] → [RBAC/Permissions] → [Input Validation] → [Handler]
                                                                                  ↓
Response ← [Response Filter] ← [Security Headers] ← [Audit Log] ← ←  ← ← ← [Result]
```

### Design principles

1. **Defense in Depth** — Multiple layers of security (network, middleware, code, database).
2. **Least Privilege** — Each token, API key, and service account has only the minimum required permissions.
3. **Zero Trust** — Never trust implicitly. Validate at every boundary, including between internal services.
4. **Fail Secure** — When something fails, deny access. Never "fail open".
5. **Secure by Default** — Default configurations should be as restrictive as possible.

---

## References

- [OWASP API Security Top 10:2023 — Official Page](https://owasp.org/API-Security/editions/2023/en/0x11-t10/)
- [OWASP API Security Project](https://owasp.org/www-project-api-security/)
- [OWASP REST Security Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/REST_Security_Cheat_Sheet.html)
- [OWASP GraphQL Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/GraphQL_Cheat_Sheet.html)
- [OWASP Authentication Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html)

---

## License

This document is released under [CC BY-SA 4.0](https://creativecommons.org/licenses/by-sa/4.0/). Based on the work of the [OWASP Foundation](https://owasp.org/).
