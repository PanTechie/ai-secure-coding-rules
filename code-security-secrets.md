# 🔑 Code Security Rules — Secrets Management

> **Version:** 1.0.0
> **Based on:** [OWASP Secrets Management Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Secrets_Management_Cheat_Sheet.html), [OWASP Cryptographic Storage](https://cheatsheetseries.owasp.org/cheatsheets/Cryptographic_Storage_Cheat_Sheet.html), [OWASP Password Storage](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html)
> **Last updated:** February 2026
> **Usage:** Place this file in `.claude/rules/` in your repository.

---

## General Instructions

When generating, reviewing, or refactoring code, **never introduce, expose, or insecurely manage any type of secret**. Secrets include: API keys, database credentials, passwords, access tokens, SSH keys, TLS certificates, encryption keys, signing keys, and any data that, if exposed, compromises system security.

This document complements the other `code-security-*` files with rules **specific to secure credential and secrets management**.

---

## 1 — Never Hardcode Secrets

The most fundamental rule. Hardcoded secrets end up in Git repositories, CI/CD logs, Docker images, build artifacts, and backups. Once committed, they remain in Git history even after removal.

### Mandatory rules

- **Zero secrets in source code** — No literal string in code should contain real credentials, tokens, keys, or passwords. This includes: configuration files, scripts, dockerfiles, notebooks, tests, and documentation.
- **Zero secrets in repositories** — Not in protected branches, not in temporary branches, not in reverted commits.
- **Use environment variables or secrets managers** — Load secrets at runtime via environment variables or calls to a secrets manager.
- **Don't commit environment files** — `.env`, `.env.local`, `.env.production` and similar must be in `.gitignore`. Provide a `.env.example` with placeholders.
- **Don't use real default values** — Defaults in code must be clearly invalid: `your-api-key-here`, `CHANGE_ME`, empty strings — never a functional value.

### Example

```python
# ❌ INSECURE — hardcoded secret
DATABASE_URL = "postgres://admin:s3cr3t_p@ss@db.prod.internal:5432/myapp"
API_KEY = "sk-abc123xyz789realkey"
STRIPE_SECRET = "sk_live_abcdef123456"

# ❌ INSECURE — "hidden" in constant but still in code
_PRIVATE_KEY = """-----BEGIN RSA PRIVATE KEY-----
MIIEpAIBAAKCAQEA0Z3VS5JJcds3xfn/ygWeCFPwF...
-----END RSA PRIVATE KEY-----"""

# ✅ SECURE — loading via environment variable
import os

DATABASE_URL = os.environ["DATABASE_URL"]          # Fails if missing (good!)
API_KEY = os.environ.get("API_KEY")                # Can be None
STRIPE_SECRET = os.environ["STRIPE_SECRET_KEY"]
```

```typescript
// ❌ INSECURE
const apiKey = "sk-abc123xyz789realkey";

// ✅ SECURE
const apiKey = process.env.API_KEY;
if (!apiKey) {
  throw new Error("API_KEY environment variable is required");
}
```

---

## 2 — Use Secrets Managers

Environment variables are the minimum. For production environments, use dedicated secrets managers that offer: encryption at rest, granular access control, auditing, automatic rotation, and versioning.

### Mandatory rules

- **Use secrets managers in production** — HashiCorp Vault, AWS Secrets Manager, Azure Key Vault, GCP Secret Manager, Infisical, Doppler, or equivalent.
- **Fetch secrets at runtime** — The application fetches secrets at startup or on demand, not as a static file.
- **Separate secrets by environment** — Dev, staging, and production must have completely distinct secrets. Never share credentials between environments.
- **Apply least privilege** — Each service/application accesses only the secrets necessary for its operation. Nobody accesses everything.
- **Audit access** — Every secret access must be logged: who, when, which secret. Alert on anomalous access.
- **Have a break-glass process** — Document and test emergency procedures in case the secrets manager becomes unavailable.

### Example

```python
# ✅ Loading secrets via AWS Secrets Manager
import boto3
import json
from functools import lru_cache

@lru_cache(maxsize=1)
def get_db_credentials() -> dict:
    client = boto3.client("secretsmanager", region_name="us-east-1")
    response = client.get_secret_value(SecretId="prod/myapp/database")
    return json.loads(response["SecretString"])

# Usage
creds = get_db_credentials()
db_url = f"postgres://{creds['username']}:{creds['password']}@{creds['host']}:{creds['port']}/{creds['dbname']}"
```

```python
# ✅ Loading secrets via HashiCorp Vault
import hvac

def get_secret(path: str) -> dict:
    client = hvac.Client(
        url=os.environ["VAULT_ADDR"],
        token=os.environ["VAULT_TOKEN"],  # Or use IAM, Kubernetes auth, etc.
    )
    response = client.secrets.kv.v2.read_secret_version(path=path)
    return response["data"]["data"]
```

```yaml
# ✅ Kubernetes — External Secrets Operator
apiVersion: external-secrets.io/v1beta1
kind: ExternalSecret
metadata:
  name: myapp-secrets
spec:
  refreshInterval: 1h
  secretStoreRef:
    name: aws-secrets-manager
    kind: ClusterSecretStore
  target:
    name: myapp-secrets
  data:
    - secretKey: DATABASE_URL
      remoteRef:
        key: prod/myapp/database
        property: url
    - secretKey: API_KEY
      remoteRef:
        key: prod/myapp/api
        property: key
```

---

## 3 — Secret Rotation

Static secrets that never change are a ticking time bomb. Regular rotation limits the exposure window in case of compromise and is a compliance requirement (PCI-DSS, SOC2, ISO 27001).

### Mandatory rules

- **Implement automatic rotation** — Use the secrets manager's native rotation feature or create automation to run regularly.
- **Define rotation policies** — Database credentials: 30-90 days. API keys: 90 days. TLS certificates: before expiration, with margin. Encryption keys: annual or per compliance.
- **Support dual credentials** — During rotation, the system must accept both old and new credentials for a transition period.
- **Rotate immediately after suspicion** — If there's any indication of compromise, rotate immediately, don't wait for the regular cycle.
- **Never reuse secrets** — Each rotation generates completely new values. Never alternate between two old values.
- **Test rotation** — Execute rotation tests regularly to confirm the process works without downtime.

### Example

```python
# ✅ Application that supports graceful API key rotation
import time

class APIKeyManager:
    """Manages API keys with support for zero-downtime rotation."""

    def __init__(self, secrets_client):
        self.secrets_client = secrets_client
        self._current_key = None
        self._previous_key = None
        self._last_refresh = 0
        self._refresh_interval = 300  # 5 minutes

    def get_current_key(self) -> str:
        if time.time() - self._last_refresh > self._refresh_interval:
            self._refresh()
        return self._current_key

    def validate_key(self, key: str) -> bool:
        """Accepts current OR previous key (transition period)."""
        self._refresh_if_needed()
        return key == self._current_key or key == self._previous_key

    def _refresh(self):
        secret = self.secrets_client.get_secret("prod/api-keys/primary")
        new_key = secret["current"]
        if new_key != self._current_key:
            self._previous_key = self._current_key
            self._current_key = new_key
            audit_log.info("API key rotated successfully")
        self._last_refresh = time.time()
```

---

## 4 — Prevent Repository Leaks

Secrets leaked in repositories (even private ones) are one of the most common causes of breaches. Implement multiple layers of prevention.

### Mandatory rules

- **Maintain strict `.gitignore`** — Include all file patterns that may contain secrets.
- **Use pre-commit hooks** — Configure hooks that scan code before each commit to detect secrets.
- **Scan in CI/CD** — Run secret scanning on every push and pull request.
- **Enable provider alerts** — Activate GitHub Secret Scanning, GitLab Secret Detection, or equivalent.
- **Scan history regularly** — Periodically scan the entire repository history for secrets that may have been committed in the past.
- **Have a leak response process** — If a secret is committed, rotate it immediately. Cleaning Git history is NOT sufficient — the secret must be considered compromised.

### Minimum `.gitignore` for secrets

```gitignore
# Environment variables
.env
.env.*
!.env.example

# Keys and certificates
*.pem
*.key
*.p12
*.pfx
*.jks
*.keystore

# Cloud credentials
.aws/credentials
.azure/credentials
gcloud-credentials.json
*-service-account*.json
*credentials*.json

# IDE and tools
.idea/
.vscode/settings.json

# Local configs with possible secrets
local_settings.py
config.local.*
secrets.*
!secrets.example.*

# Docker
docker-compose.override.yml

# Terraform
*.tfstate
*.tfstate.backup
*.tfvars
!*.tfvars.example
.terraform/
```

### Pre-commit hook with Gitleaks

```yaml
# .pre-commit-config.yaml
repos:
  - repo: https://github.com/pre-commit/pre-commit-hooks
    rev: v5.0.0
    hooks:
      - id: check-yaml
      - id: check-json
      - id: detect-private-key # Detects private keys
      - id: check-added-large-files # Prevents large files (possible dumps)

  - repo: https://github.com/gitleaks/gitleaks
    rev: v8.24.2
    hooks:
      - id: gitleaks
```

```yaml
# GitHub Actions — secret scanning in CI
name: Security - Secret Scanning
on:
  push:
    branches: [main, develop]
  pull_request:

jobs:
  gitleaks:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0

      - uses: gitleaks/gitleaks-action@v2
        env:
          GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
```

### Leak response process

```
1. DETECT   → Secret found in commit/PR
2. ROTATE   → Immediately generate new secret and revoke the old one
3. ASSESS   → Check if the secret was used by third parties (access logs)
4. CLEAN    → Remove from Git history (git filter-repo / BFG Repo Cleaner)
5. NOTIFY   → Inform team and stakeholders based on severity
6. PREVENT  → Review how the leak occurred and strengthen controls
```

---

## 5 — Secrets in CI/CD

CI/CD pipelines are high-privilege environments that frequently store and handle secrets. Pipeline compromise compromises everything it accesses.

### Mandatory rules

- **Use platform-native secrets** — GitHub Secrets, GitLab CI/CD Variables (masked + protected), AWS Parameter Store, etc. Never hardcode secrets in pipeline definitions.
- **Mask secrets in logs** — Configure the CI/CD platform to automatically mask secret values. Validate that masking works.
- **Limit secret scope** — Secrets must be accessible only by the jobs, stages, and branches that need them. Use environment-scoped secrets.
- **Don't pass secrets via command-line arguments** — Arguments appear in `ps`, `/proc`, and logs. Use environment variables or temporary files.
- **Never print secrets** — Even in debug mode, never use `echo $SECRET` or `print(os.environ["SECRET"])` in CI/CD scripts.
- **Prefer temporary credentials** — Use OIDC federation (GitHub Actions → AWS, Azure, GCP) instead of static access keys.
- **Protect pipeline as production** — Runner hardening, regular patches, restricted access to pipeline configuration.

### Example

```yaml
# ✅ GitHub Actions with OIDC Federation (no static access keys)
name: Deploy
on:
  push:
    branches: [main]

permissions:
  id-token: write # Required for OIDC
  contents: read

jobs:
  deploy:
    runs-on: ubuntu-latest
    environment: production # Environment-scoped secrets

    steps:
      - uses: actions/checkout@v4

      # ✅ OIDC federation — no hardcoded access keys
      - uses: aws-actions/configure-aws-credentials@v4
        with:
          role-to-assume: arn:aws:iam::123456789012:role/github-deploy
          aws-region: us-east-1

      # ❌ NEVER do this
      # - run: echo "Key is ${{ secrets.AWS_SECRET_KEY }}"
      # - run: aws configure set aws_secret_access_key ${{ secrets.AWS_SECRET_KEY }}

      - run: ./scripts/deploy.sh
        env:
          APP_ENV: production
          # Secrets via env vars, not arguments
          DATABASE_URL: ${{ secrets.DATABASE_URL }}
```

---

## 6 — Secrets in Containers and Kubernetes

Containers introduce additional challenges: publicly accessible images, layers that preserve history, environment variables visible via `docker inspect`.

### Mandatory rules

- **Never include secrets in Docker images** — Secrets in `COPY`, `ADD`, or `ENV` are permanently in image layers, even if "removed" in later layers.
- **Use multi-stage builds** — If secrets are needed during build (e.g., tokens for private registries), use multi-stage and never copy secrets to the final stage.
- **Use Docker BuildKit secrets** — For build-time secrets, use `--mount=type=secret` which doesn't persist in layers.
- **Use Kubernetes Secrets (with encryption)** — Enable encryption-at-rest for Secrets in etcd. By default, Kubernetes Secrets are only base64 encoded, not encrypted.
- **Prefer External Secrets Operator** — Sync secrets from an external secrets manager instead of creating them manually.
- **Mount secrets as volumes, not env vars** — Secrets mounted as files can be updated without restart; env vars cannot. Additionally, env vars can leak in crash logs.

### Example

```dockerfile
# ❌ INSECURE — secret persists in image layers
FROM node:20
COPY .env /app/.env
ENV API_KEY=sk-abc123
RUN npm install

# ❌ INSECURE — later removal doesn't delete from previous layer
FROM node:20
COPY credentials.json /tmp/credentials.json
RUN setup-tool --credentials /tmp/credentials.json
RUN rm /tmp/credentials.json  # Still visible in previous layer!

# ✅ SECURE — multi-stage + BuildKit secrets
FROM node:20 AS builder
WORKDIR /app
COPY package*.json ./
# Secret available only during this RUN, doesn't persist
RUN --mount=type=secret,id=npm_token \
    NPM_TOKEN=$(cat /run/secrets/npm_token) npm ci
COPY . .
RUN npm run build

FROM node:20-slim AS runtime
WORKDIR /app
COPY --from=builder /app/dist ./dist
COPY --from=builder /app/node_modules ./node_modules
# No secrets in final image
USER node
CMD ["node", "dist/server.js"]
```

```bash
# Build with injected BuildKit secret
DOCKER_BUILDKIT=1 docker build \
  --secret id=npm_token,src=$HOME/.npmrc \
  -t myapp:latest .
```

```yaml
# ✅ Kubernetes — secret as volume (not env var)
apiVersion: v1
kind: Pod
spec:
  containers:
    - name: myapp
      image: myapp:latest
      volumeMounts:
        - name: db-credentials
          mountPath: /etc/secrets/db
          readOnly: true
  volumes:
    - name: db-credentials
      secret:
        secretName: myapp-db-credentials
        defaultMode: 0400 # Read-only for owner
```

---

## 7 — Secure Password Hashing

User passwords require specific treatment: one-way hashing with brute-force resistant algorithms, unique salting, and adequate work factors.

### Mandatory rules

- **Use modern algorithms** — In order of preference: **Argon2id** (preferred), **bcrypt** (widely supported), **scrypt** (good for memory-limited environments). For FIPS-140 compliance: PBKDF2 with HMAC-SHA-256.
- **Never use generic hashes** — MD5, SHA-1, plain SHA-256/SHA-512 are NOT suitable for passwords, even with salt. They're too fast, which facilitates brute force.
- **Use unique salt per password** — Each password must have its own random salt. Modern libraries (argon2, bcrypt) generate salt automatically.
- **Configure adequate work factor** — bcrypt: cost ≥ 12. Argon2id: time_cost ≥ 3, memory_cost ≥ 64MB, parallelism ≥ 2. PBKDF2: iterations ≥ 600,000 (SHA-256). Target ~250ms per hash.
- **Consider pepper** — Add a secret (pepper) stored outside the database before hashing. If the database leaks, the pepper protects passwords.
- **Never decrypt passwords** — Passwords are hashed, not encrypted. There must be no way to recover the original password.
- **Upgrade hashes** — If the system uses legacy algorithms, rehash on successful login with the current algorithm.

### Example

```python
# ❌ INSECURE — generic hash
import hashlib
hashed = hashlib.sha256(password.encode()).hexdigest()

# ❌ INSECURE — MD5 (even with salt)
hashed = hashlib.md5((salt + password).encode()).hexdigest()

# ✅ SECURE — Argon2id (preferred)
from argon2 import PasswordHasher

ph = PasswordHasher(
    time_cost=3,          # Iterations
    memory_cost=65536,    # 64MB memory
    parallelism=4,        # 4 threads
    hash_len=32,          # Hash length
    type=argon2.Type.ID,  # Argon2id (resistant to side-channel and GPU)
)

# Hash
hashed = ph.hash(password)
# Result: $argon2id$v=19$m=65536,t=3,p=4$salt$hash

# Verification
try:
    ph.verify(hashed, password_attempt)
    # Rehash if parameters changed
    if ph.check_needs_rehash(hashed):
        new_hash = ph.hash(password_attempt)
        update_user_password_hash(user_id, new_hash)
except argon2.exceptions.VerifyMismatchError:
    handle_failed_login()
```

```python
# ✅ SECURE — bcrypt (widely supported alternative)
import bcrypt

# Hash
hashed = bcrypt.hashpw(
    password.encode("utf-8"),
    bcrypt.gensalt(rounds=12),  # Cost factor 12 (recommended minimum)
)

# Verification
if bcrypt.checkpw(password_attempt.encode("utf-8"), hashed):
    authenticate_user()
```

```python
# ✅ Pepper (additional layer with HMAC)
import hmac
import hashlib

PEPPER = os.environ["PASSWORD_PEPPER"]  # Secret stored outside DB

def hash_password_with_pepper(password: str) -> str:
    peppered = hmac.new(
        PEPPER.encode(), password.encode(), hashlib.sha384
    ).digest()
    # Then apply Argon2id/bcrypt to the HMAC result
    return ph.hash(peppered)
```

---

## 8 — Encryption Keys

Encryption keys (DEKs, KEKs, signing keys) require complete lifecycle management: secure generation, isolated storage, rotation, and destruction.

### Mandatory rules

- **Generate keys with CSPRNG** — Use cryptographically secure generators: `secrets` (Python), `crypto.randomBytes()` (Node.js), `/dev/urandom` (Linux). Never `Math.random()` or `random.random()`.
- **Separate keys from data** — Encryption keys must be in a different location from encrypted data. If the database leaks, the keys must not leak with it.
- **Implement envelope encryption** — Use a Key Encryption Key (KEK) to encrypt Data Encryption Keys (DEKs). The KEK stays in KMS; DEKs are stored encrypted alongside data.
- **Use managed KMS** — AWS KMS, Azure Key Vault, GCP Cloud KMS, or HSMs for high-sensitivity keys.
- **Rotate keys periodically** — Implement rotation that re-encrypts data with the new key. Keep old keys for decrypting legacy data.
- **Destroy keys securely** — When a key is no longer needed, destroy it in a way that prevents recovery.
- **Use modern algorithms** — AES-256-GCM (symmetric encryption), RSA-OAEP with ≥2048 bits or ECDSA P-256+ (asymmetric), Ed25519 (signatures).

### Example

```python
# ❌ INSECURE — key generation and usage
import random
key = ''.join(random.choice('abcdef0123456789') for _ in range(32))  # NOT cryptographic!

# ✅ SECURE — key generation with CSPRNG
import secrets
key = secrets.token_bytes(32)  # 256 bits

# ✅ SECURE — encryption with AES-256-GCM
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

def encrypt(plaintext: bytes, key: bytes) -> bytes:
    """Encrypts with AES-256-GCM. Returns nonce || ciphertext."""
    nonce = secrets.token_bytes(12)  # 96-bit nonce for GCM
    aesgcm = AESGCM(key)
    ciphertext = aesgcm.encrypt(nonce, plaintext, associated_data=None)
    return nonce + ciphertext

def decrypt(data: bytes, key: bytes) -> bytes:
    """Decrypts AES-256-GCM. Expects nonce || ciphertext."""
    nonce = data[:12]
    ciphertext = data[12:]
    aesgcm = AESGCM(key)
    return aesgcm.decrypt(nonce, ciphertext, associated_data=None)
```

---

## 9 — Secrets in Logs and Observability

Secrets frequently leak via logs, stack traces, metrics, APM, and error tracking. A log with `DATABASE_URL=postgres://admin:password@host` in a centralized system is as dangerous as hardcoding.

### Mandatory rules

- **Never log secrets** — Implement filters that redact sensitive values automatically before writing logs.
- **Sanitize stack traces** — Connection errors frequently include connection strings with credentials. Filter before sending to error tracking.
- **Don't include secrets in metrics and traces** — Metric labels and tracing spans must not contain secret values.
- **Mask across the entire stack** — Filters must exist in the application, in the log collector, and in the storage system.

### Example

```python
# ✅ Secret filter for logging
import re
import logging

REDACT_PATTERNS = [
    (r'(?i)(password|passwd|pwd|secret|token|api[_-]?key|authorization)\s*[=:]\s*\S+',
     r'\1=***REDACTED***'),
    (r'(?i)(bearer\s+)\S+', r'\1***REDACTED***'),
    (r'://\w+:\S+@', r'://***:***@'),                     # Connection strings
    (r'\b(sk|pk|api)[_-][\w]{20,}\b', '***REDACTED_KEY***'),
    (r'\bAKIA[0-9A-Z]{16}\b', '***REDACTED_AWS_KEY***'),
    (r'\b(ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9_]{36,}\b', '***REDACTED_GH_TOKEN***'),
]

class SecretRedactingFilter(logging.Filter):
    def filter(self, record):
        if isinstance(record.msg, str):
            for pattern, replacement in REDACT_PATTERNS:
                record.msg = re.sub(pattern, replacement, record.msg)
        return True

# Apply to all logging
logger = logging.getLogger()
logger.addFilter(SecretRedactingFilter())
```

---

## 10 — Tokens and Sessions

API tokens, sessions, and temporary credentials have their own lifecycle that must be rigorously managed.

### Mandatory rules

- **Short-lived tokens** — Access tokens: 5-15 minutes. Refresh tokens: hours to days, with rotation on each use.
- **Minimum scope** — Each token must have only the necessary permissions. Prefer tokens with granular scopes.
- **Revoke on logout** — Tokens must be revocable server-side. Logout must invalidate all associated tokens.
- **Transmit via headers** — Never in query strings (they appear in server and proxy logs). Use `Authorization: Bearer ...`.
- **Store securely** — Browser: `HttpOnly`, `Secure`, `SameSite=Strict` cookies. Mobile: secure keychain/keystore. Backend: memory or secure storage.
- **Don't expose in client-side** — API keys with write permission must never be in frontend code (JS, mobile). Use a backend proxy.

### Example

```python
# ✅ Client-side API key via backend proxy
# Frontend calls YOUR backend, which adds the API key server-side

# Frontend (does NOT have the API key)
# fetch("/api/proxy/weather?city=london")

# Backend (HAS the API key)
@app.route("/api/proxy/weather")
@require_auth
@limiter.limit("30 per minute")
def weather_proxy():
    city = request.args.get("city")
    response = requests.get(
        "https://api.weather.example.com/v1/current",
        params={"city": city},
        headers={"Authorization": f"Bearer {os.environ['WEATHER_API_KEY']}"},
        timeout=10,
    )
    # Return only necessary data (don't forward headers/metadata)
    data = response.json()
    return jsonify({"temp": data["temp"], "condition": data["condition"]})
```

---

## Quick Checklist for Code Review

| #   | Category          | Key question                                                                          |
| --- | ----------------- | ------------------------------------------------------------------------------------- |
| 1   | Hardcoded Secrets | Is there any literal string that looks like a real credential, token, or key?         |
| 2   | Secrets Managers  | Are production secrets loaded via secrets manager or at least env vars?               |
| 3   | Rotation          | Is there a rotation process? Does the app support dual credentials during transition? |
| 4   | Git Prevention    | Does `.gitignore` cover sensitive files? Are pre-commit hooks configured?             |
| 5   | CI/CD             | Are pipeline secrets masked, scoped, and preferably via OIDC federation?              |
| 6   | Containers        | Does Dockerfile use multi-stage and BuildKit secrets? No secrets in layers?           |
| 7   | Password Hashing  | Do passwords use Argon2id/bcrypt with adequate work factor? Never plain MD5/SHA?      |
| 8   | Encryption Keys   | Are keys generated with CSPRNG, stored in KMS, and rotated?                           |
| 9   | Logs              | Are redaction filters active? Are connection strings and tokens masked?               |
| 10  | Tokens            | Do tokens have short duration, minimum scope, and are revocable?                      |

---

## Detection Patterns — What to Scan

To configure scanning tools, detect at least these patterns:

| Type              | Pattern (simplified regex)                              |
| ----------------- | ------------------------------------------------------- |
| AWS Access Key    | `AKIA[0-9A-Z]{16}`                                      |
| AWS Secret Key    | `(?i)aws_secret_access_key\s*=\s*\S{40}`                |
| GitHub Token      | `(ghp\|gho\|ghu\|ghs\|ghr)_[A-Za-z0-9_]{36,}`           |
| Generic API Key   | `(?i)(api[_-]?key\|apikey)\s*[=:]\s*['"]?\w{20,}`       |
| Generic Secret    | `(?i)(secret\|password\|passwd\|token)\s*[=:]\s*\S{8,}` |
| Private Key       | `-----BEGIN (RSA\|EC\|DSA\|OPENSSH) PRIVATE KEY-----`   |
| Connection String | `(?i)(postgres\|mysql\|mongodb)://\w+:\S+@`             |
| Slack Token       | `xox[baprs]-[0-9a-zA-Z-]{10,}`                          |
| Stripe Key        | `(sk\|pk)_(live\|test)_[0-9a-zA-Z]{24,}`                |
| JWT               | `eyJ[A-Za-z0-9-_]+\.eyJ[A-Za-z0-9-_]+\.[A-Za-z0-9-_]+`  |

---

## References

- [OWASP Secrets Management Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Secrets_Management_Cheat_Sheet.html)
- [OWASP Password Storage Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html)
- [OWASP Cryptographic Storage Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Cryptographic_Storage_Cheat_Sheet.html)
- [OWASP Key Management Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Key_Management_Cheat_Sheet.html)
- [Gitleaks — Secret Scanning](https://github.com/gitleaks/gitleaks)
- [NIST SP 800-63B — Digital Identity Guidelines](https://pages.nist.gov/800-63-3/sp800-63b.html)

---

## License

This document is released under [CC BY-SA 4.0](https://creativecommons.org/licenses/by-sa/4.0/). Based on the work of the [OWASP Foundation](https://owasp.org/).
