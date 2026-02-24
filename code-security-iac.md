# 🛡️ Code Security Rules — Infrastructure as Code (IaC)

> **Version:** 2.0.0
> **Based on:** OWASP Docker Top 10, OWASP Kubernetes Top 10, OWASP CI/CD Top 10, CIS Benchmarks (Docker, Kubernetes), NSA/CISA Kubernetes Hardening Guide v1.2, Terraform/CloudFormation best practices
> **Last updated:** February 2026
> **Replaces:** `code-security-infrastructure.md` v1.0.0
> **Usage:** Place this file in `.claude/rules/` (Claude Code), `.agent/rules/` (Antigravity), or `.cursor/rules/` (Cursor).

---

## General Instructions

When generating, reviewing, or refactoring infrastructure code — including Dockerfiles, Kubernetes manifests, Helm charts, Terraform/OpenTofu, CloudFormation, Pulumi, CI/CD pipelines, or cloud provider configurations — **always apply the following security rules**. Treat each rule as mandatory. When in doubt between convenience and security, **prioritize security**.

### Source Frameworks

| Framework                               | Coverage                           | Section |
| --------------------------------------- | ---------------------------------- | ------- |
| OWASP Docker Top 10                     | Container image & runtime security | §1–§2   |
| CIS Docker Benchmark v1.8               | Prescriptive container hardening   | §1–§2   |
| OWASP Kubernetes Top 10                 | K8s-specific risks (K01–K10)       | §3      |
| CIS Kubernetes Benchmark                | K8s configuration hardening        | §3      |
| NSA/CISA K8s Hardening Guide v1.2       | Threat model + strategic hardening | §3      |
| OWASP CI/CD Top 10                      | Pipeline security (CICD-SEC-01–10) | §4      |
| Terraform/CloudFormation best practices | IaC template hardening             | §5      |
| CIS Cloud Benchmarks (AWS/Azure/GCP)    | Cloud provider hardening           | §6      |

---

## Section 1 — Container Images (Build-Time Security)

Covers OWASP Docker Top 10: D1 (Secure User Mapping), D2 (Patch Management), D4 (Least Privilege). CIS Docker Benchmark Section 4.

### Mandatory rules

- **Never run containers as root** — Every Dockerfile must include a `USER` directive with a non-root user. This is the single most impactful container security control.
- **Use minimal base images** — Prefer `distroless`, `alpine`, or `-slim` variants. Avoid full OS images (`ubuntu`, `debian`) unless dependencies require them. Smaller images have fewer vulnerabilities.
- **Pin image versions** — Never use `:latest` tag. Pin to specific versions or digests (`image@sha256:...`). This ensures reproducible builds and prevents supply chain tampering.
- **Use multi-stage builds** — Separate build dependencies from runtime. The final stage should contain only the application binary and runtime dependencies, not compilers, SDKs, or build tools.
- **Scan images for vulnerabilities** — Integrate image scanning (Trivy, Grype, Snyk Container) into CI/CD. Block deployments of images with CRITICAL or HIGH CVEs.
- **Do not store secrets in images** — Never use `ARG` or `ENV` for secrets in Dockerfiles. Secrets embedded in layers are extractable even after deletion. Use runtime secret injection.
- **Minimize layers and clean up** — Combine `RUN` commands to reduce layers. Remove package manager caches, temp files, and build artifacts in the same layer they're created.
- **Set HEALTHCHECK** — Define health check instructions to enable orchestrators to detect unhealthy containers.
- **Use COPY, not ADD** — Prefer `COPY` over `ADD` unless you need auto-extraction of tar files. `ADD` can fetch remote URLs and auto-extract archives, increasing attack surface.
- **Sign and verify images** — Sign container images with Cosign or Docker Content Trust. Verify signatures before deployment.

```dockerfile
# ❌ INSECURE — multiple violations
FROM ubuntu:latest
RUN apt-get update && apt-get install -y python3 python3-pip
COPY . /app
ENV DATABASE_PASSWORD=s3cret
RUN pip install -r /app/requirements.txt
EXPOSE 8080
CMD ["python3", "/app/main.py"]

# ✅ SECURE — hardened multi-stage build
FROM python:3.12-slim AS builder
WORKDIR /build
COPY requirements.txt .
RUN pip install --no-cache-dir --target=/deps -r requirements.txt

FROM gcr.io/distroless/python3-debian12:nonroot
COPY --from=builder /deps /deps
COPY --chown=nonroot:nonroot ./app /app
ENV PYTHONPATH=/deps
EXPOSE 8080
USER nonroot
HEALTHCHECK --interval=30s --timeout=5s --retries=3 \
  CMD ["/app/healthcheck.py"]
ENTRYPOINT ["python3", "/app/main.py"]
```

### .dockerignore (always include)

```
.git
.env
*.pem
*.key
*.secret
node_modules
__pycache__
.terraform
*.tfstate
*.tfvars
```

---

## Section 2 — Container Runtime Security

Covers OWASP Docker Top 10: D3 (Network Segmentation), D5 (Filesystem/Volumes), D6 (Logging), D7 (Resource Limits), D9 (Default Security). CIS Docker Benchmark Sections 2, 3, 5.

### Mandatory rules

- **Drop all capabilities, add only what's needed** — Start with `--cap-drop=ALL` and selectively add required capabilities. Most applications need zero Linux capabilities.
- **Use read-only root filesystem** — Mount the container's root filesystem as read-only (`--read-only`). Use `tmpfs` mounts for directories that require write access.
- **Set resource limits** — Always define CPU and memory limits. Unlimited containers can exhaust host resources (DoS).
- **Disable privilege escalation** — Set `--security-opt=no-new-privileges` to prevent processes from gaining additional privileges via setuid/setgid binaries.
- **Do not use privileged mode** — Never use `--privileged`. It gives the container full access to the host, equivalent to root on the host machine.
- **Do not share the host network namespace** — Avoid `--network=host`. It gives the container full access to the host's network stack.
- **Do not mount the Docker socket** — Never mount `/var/run/docker.sock` into containers. It gives the container full control over the Docker daemon (container escape).
- **Use user namespaces** — Enable user namespace remapping to map container root to a non-root host user.
- **Limit syscalls with seccomp** — Apply a seccomp profile to restrict system calls. Use the default Docker seccomp profile at minimum, or create a custom restrictive profile.
- **Apply SELinux/AppArmor profiles** — Use mandatory access control (MAC) profiles to confine container processes.
- **Configure logging** — Set logging driver and options. Forward container logs to a centralized system. Do not rely on `docker logs` in production.
- **Use a dedicated network** — Create user-defined bridge networks for inter-container communication. Do not use the default bridge network.

```yaml
# ✅ SECURE — docker-compose.yml with hardened runtime
services:
  api:
    image: myapp/api:1.2.3@sha256:abc123...
    read_only: true
    user: "1000:1000"
    security_opt:
      - no-new-privileges:true
      - seccomp:./seccomp-profile.json
    cap_drop:
      - ALL
    cap_add:
      - NET_BIND_SERVICE # Only if binding to ports < 1024
    deploy:
      resources:
        limits:
          cpus: "1.0"
          memory: 512M
        reservations:
          cpus: "0.25"
          memory: 128M
    tmpfs:
      - /tmp:size=64M
      - /app/cache:size=32M
    networks:
      - internal
    healthcheck:
      test: ["CMD", "curl", "-f", "http://localhost:8080/health"]
      interval: 30s
      timeout: 5s
      retries: 3

networks:
  internal:
    driver: bridge
    internal: true # No external access
```

---

## Section 3 — Kubernetes Security

Covers OWASP Kubernetes Top 10 (K01–K10), CIS Kubernetes Benchmark, NSA/CISA Kubernetes Hardening Guide v1.2.

### K01 — Insecure Workload Configuration

- **Set SecurityContext on every Pod/Container** — Define `runAsNonRoot: true`, `readOnlyRootFilesystem: true`, `allowPrivilegeEscalation: false`, and drop all capabilities.
- **Never use `privileged: true`** — No workload should run in privileged mode unless absolutely required (and then only with compensating controls and explicit security review).
- **Set `automountServiceAccountToken: false`** — Unless the pod needs to call the Kubernetes API, disable automatic mounting of the service account token.

```yaml
# ✅ SECURE — hardened Pod SecurityContext
apiVersion: v1
kind: Pod
metadata:
  name: secure-app
spec:
  automountServiceAccountToken: false
  securityContext:
    runAsNonRoot: true
    runAsUser: 1000
    runAsGroup: 1000
    fsGroup: 1000
    seccompProfile:
      type: RuntimeDefault
  containers:
    - name: app
      image: myapp/api:1.2.3@sha256:abc123
      securityContext:
        allowPrivilegeEscalation: false
        readOnlyRootFilesystem: true
        capabilities:
          drop: ["ALL"]
      resources:
        limits:
          cpu: "500m"
          memory: "256Mi"
        requests:
          cpu: "100m"
          memory: "128Mi"
      volumeMounts:
        - name: tmp
          mountPath: /tmp
  volumes:
    - name: tmp
      emptyDir:
        sizeLimit: 64Mi
```

### K02 — Supply Chain Vulnerabilities

- **Scan images in CI and admission** — Scan images for CVEs before push and at admission (using admission controllers like Kyverno, OPA Gatekeeper, or Kubewarden).
- **Enforce image pull from trusted registries only** — Use admission policies to allow images only from approved registries.
- **Require image signatures** — Enforce that all deployed images are signed (Cosign/Sigstore) via admission controllers.
- **Pin image digests in production** — Use `image: registry/app@sha256:...` instead of mutable tags.
- **Scan for SBOM and license compliance** — Generate and validate Software Bill of Materials (SBOM) for all container images.

### K03 — Overly Permissive RBAC

- **Follow least privilege for RBAC** — Grant the minimum verbs and resources needed. Never use `*` wildcards in production roles.
- **Avoid ClusterRoleBindings when possible** — Prefer namespaced RoleBindings over cluster-wide bindings.
- **Do not bind to `cluster-admin`** — The `cluster-admin` ClusterRole grants unlimited access. Never bind it to service accounts or users in application namespaces.
- **Audit RBAC regularly** — Use tools like `rbac-police`, `kubectl-who-can`, or Kubescape to identify over-permissive roles.
- **Separate admin and application service accounts** — Application workloads must use dedicated service accounts, never the `default` service account.

```yaml
# ❌ INSECURE — overly permissive RBAC
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: app-admin
roleRef:
  kind: ClusterRole
  name: cluster-admin    # NEVER do this
  apiGroup: rbac.authorization.k8s.io
subjects:
  - kind: ServiceAccount
    name: default         # NEVER use default SA
    namespace: production

# ✅ SECURE — scoped RBAC
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: app-reader
  namespace: production
rules:
  - apiGroups: [""]
    resources: ["configmaps"]
    verbs: ["get", "list"]
    resourceNames: ["app-config"]  # Restrict to specific resources
---
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  name: app-reader-binding
  namespace: production
roleRef:
  kind: Role
  name: app-reader
  apiGroup: rbac.authorization.k8s.io
subjects:
  - kind: ServiceAccount
    name: app-service-account
    namespace: production
```

### K04 — Lack of Centralized Policy Enforcement

- **Deploy a policy engine** — Use Kyverno, OPA/Gatekeeper, or Kubewarden for cluster-wide policy enforcement.
- **Enforce Pod Security Standards** — Apply Kubernetes Pod Security Standards (PSS) at namespace level using Pod Security Admission: `restricted` for production, `baseline` for staging.
- **Block privileged workloads via policy** — Admission policies must reject pods with `privileged: true`, `hostNetwork: true`, `hostPID: true`, `hostIPC: true`.

```yaml
# ✅ SECURE — Pod Security Standards enforcement
apiVersion: v1
kind: Namespace
metadata:
  name: production
  labels:
    pod-security.kubernetes.io/enforce: restricted
    pod-security.kubernetes.io/audit: restricted
    pod-security.kubernetes.io/warn: restricted
```

### K05 — Inadequate Logging and Monitoring

- **Enable Kubernetes audit logging** — Configure the API server with an audit policy that logs authentication, authorization, and resource changes.
- **Centralize log collection** — Ship container logs, node logs, and audit logs to a centralized SIEM (ELK, Loki, Splunk, Datadog).
- **Monitor for anomalies** — Alert on: failed authentication, RBAC changes, container exec operations, privileged pod creation, and secrets access.
- **Enable runtime threat detection** — Deploy Falco, Tetragon, or similar runtime security tools to detect malicious behavior inside containers.

### K06 — Broken Authentication

- **Disable anonymous authentication** — Set `--anonymous-auth=false` on the API server (unless specifically required and compensated).
- **Use short-lived tokens** — Prefer bound service account tokens (projected volumes) over static long-lived tokens.
- **Integrate with external identity providers** — Use OIDC integration for human access. Avoid client certificates for user authentication.

### K07 — Missing Network Segmentation

- **Implement NetworkPolicies** — Every namespace must have a default-deny ingress and egress NetworkPolicy. Then add allow rules explicitly.
- **Isolate sensitive workloads** — Databases, internal APIs, and control plane components should only be reachable from specific namespaces/pods.
- **Use a CNI that supports NetworkPolicies** — Verify your CNI plugin (Calico, Cilium, Weave) actually enforces policies. The default `kubenet` does not.

```yaml
# ✅ SECURE — default deny all + selective allow
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: default-deny-all
  namespace: production
spec:
  podSelector: {}
  policyTypes:
    - Ingress
    - Egress
---
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: allow-api-to-db
  namespace: production
spec:
  podSelector:
    matchLabels:
      app: database
  policyTypes:
    - Ingress
  ingress:
    - from:
        - podSelector:
            matchLabels:
              app: api
      ports:
        - port: 5432
          protocol: TCP
```

### K08 — Secrets Management Failures

- **Never store secrets in manifests or ConfigMaps** — Use Kubernetes Secrets as a minimum, but prefer external secret managers (Vault, AWS Secrets Manager, Azure Key Vault, GCP Secret Manager).
- **Enable encryption at rest for etcd** — Configure the API server `--encryption-provider-config` to encrypt secrets stored in etcd.
- **Use external secrets operators** — Deploy External Secrets Operator, Vault Injector, or Sealed Secrets to sync secrets from external vaults.
- **Rotate secrets automatically** — Implement automated rotation for all credentials, certificates, and tokens.

```yaml
# ❌ INSECURE — secret in plain ConfigMap
apiVersion: v1
kind: ConfigMap
metadata:
  name: app-config
data:
  DATABASE_URL: "postgres://admin:password123@db:5432/mydb"

# ✅ SECURE — ExternalSecret from Vault
apiVersion: external-secrets.io/v1beta1
kind: ExternalSecret
metadata:
  name: app-secrets
  namespace: production
spec:
  refreshInterval: 1h
  secretStoreRef:
    name: vault-backend
    kind: ClusterSecretStore
  target:
    name: app-secrets
  data:
    - secretKey: DATABASE_URL
      remoteRef:
        key: production/database
        property: connection_string
```

### K09 — Misconfigured Cluster Components

- **Secure the API server** — Disable insecure port, enable TLS, use RBAC authorization mode, enable admission controllers (PodSecurity, NodeRestriction, etc.).
- **Secure etcd** — Enable mutual TLS between API server and etcd. Restrict network access to etcd. Use a separate CA for etcd certificates.
- **Secure kubelet** — Disable anonymous kubelet authentication (`--anonymous-auth=false`), enable webhook authentication, set `--authorization-mode=Webhook`.
- **Disable unnecessary components** — Remove the Kubernetes Dashboard unless actively needed. Disable profiling endpoints.

### K10 — Outdated and Vulnerable Components

- **Keep Kubernetes up to date** — Run supported versions (N, N-1, N-2). Apply security patches promptly.
- **Update node OS and container runtime** — Regularly patch the host OS, containerd/CRI-O, and supporting components.
- **Monitor for CVEs** — Subscribe to Kubernetes security announcements and CNI/runtime security advisories.

---

## Section 4 — CI/CD Pipeline Security

Covers OWASP Top 10 CI/CD Security Risks (CICD-SEC-01 through CICD-SEC-10).

### CICD-SEC-01 — Insufficient Flow Control

- **Require code review before merge** — Enable branch protection with mandatory pull request reviews. No direct pushes to main/production branches.
- **Require CI to pass before merge** — Status checks (tests, linting, security scans) must be required and passing before merging.
- **Enforce separation of duties** — The person who writes code should not be the same person who approves and merges it.
- **Protect deployment pipelines** — Require manual approval gates for production deployments. No single actor should be able to push code to production without review.

```yaml
# ✅ SECURE — GitHub branch protection (settings.yml)
# Apply via GitHub API or repository settings
branches:
  main:
    protection:
      required_pull_request_reviews:
        required_approving_review_count: 2
        dismiss_stale_reviews: true
        require_code_owner_reviews: true
      required_status_checks:
        strict: true
        contexts:
          - "ci/tests"
          - "ci/security-scan"
          - "ci/lint"
      enforce_admins: true
      restrictions: null
```

### CICD-SEC-02 — Inadequate Identity and Access Management

- **Apply least privilege to CI/CD identities** — Pipeline service accounts, tokens, and API keys must have minimum required permissions. Never use admin/owner tokens.
- **Use ephemeral credentials** — Prefer OIDC federation (GitHub Actions → AWS/GCP/Azure) over long-lived secrets. Use workload identity, not static keys.
- **Separate environments** — Different pipelines for dev/staging/production. Production pipelines have stricter access controls and separate credentials.
- **Audit CI/CD access regularly** — Review who has admin access to CI/CD systems, who can modify pipeline definitions, and who can access secrets.

```yaml
# ✅ SECURE — GitHub Actions with OIDC (no static credentials)
permissions:
  id-token: write
  contents: read

jobs:
  deploy:
    runs-on: ubuntu-latest
    steps:
      - uses: aws-actions/configure-aws-credentials@v4
        with:
          role-to-assume: arn:aws:iam::123456789:role/deploy-role
          aws-region: us-east-1
          # No static AWS_ACCESS_KEY_ID / AWS_SECRET_ACCESS_KEY needed
```

### CICD-SEC-03 — Dependency Chain Abuse

- **Use lockfiles and verify checksums** — Always commit lockfiles (`package-lock.json`, `Pipfile.lock`, `go.sum`, `Cargo.lock`). Verify checksums on install.
- **Use private/internal package registries** — Proxy external packages through an internal registry (Artifactory, Nexus, GitHub Packages). Claim your internal package names in public registries to prevent dependency confusion.
- **Pin dependency versions** — Never use floating version ranges in production builds. Pin exact versions.
- **Scan dependencies for vulnerabilities** — Run `npm audit`, `pip-audit`, `cargo audit`, Dependabot, or Snyk in every pipeline run.
- **Review new dependencies** — New direct dependencies should require explicit review and approval.

### CICD-SEC-04 — Poisoned Pipeline Execution (PPE)

- **Protect pipeline configuration files** — `.github/workflows/*.yml`, `Jenkinsfile`, `.gitlab-ci.yml`, `Dockerfile` must be protected from modification by untrusted contributors.
- **Do not run untrusted code with secrets** — Fork PRs and external contributions must not have access to repository secrets. Use `pull_request_target` cautiously.
- **Isolate untrusted builds** — Run builds from external contributors in sandboxed environments without access to production secrets or internal networks.
- **Review pipeline changes** — Any change to CI/CD configuration must go through code review.

```yaml
# ✅ SECURE — GitHub Actions: restrict secrets from forks
on:
  pull_request:
    branches: [main]

jobs:
  test:
    runs-on: ubuntu-latest
    # Forks do NOT get secrets (default behavior for pull_request)
    steps:
      - uses: actions/checkout@v4
      - run: npm ci
      - run: npm test
```

### CICD-SEC-05 — Insufficient Pipeline-Based Access Controls (PBAC)

- **Scope pipeline permissions minimally** — In GitHub Actions, set `permissions` explicitly at the job level. Never use default `write-all`.
- **Restrict what pipelines can access** — Limit which secrets, environments, and deployment targets each pipeline can reach.
- **Use environment protection rules** — Require approval for deployments to production environments.

```yaml
# ❌ INSECURE — default permissions (often write-all)
on: push
jobs:
  build:
    runs-on: ubuntu-latest

# ✅ SECURE — explicit minimal permissions
on: push
permissions:
  contents: read
  packages: write

jobs:
  build:
    runs-on: ubuntu-latest
    permissions:
      contents: read  # Redundant but explicit
```

### CICD-SEC-06 — Insufficient Credential Hygiene

- **Never hardcode secrets in pipeline files** — Use the CI/CD system's secret management (GitHub Secrets, GitLab CI Variables, Jenkins Credentials).
- **Do not print secrets in logs** — Mask all secrets in CI output. Review pipeline output for accidental credential exposure.
- **Rotate CI/CD credentials regularly** — Rotate tokens, API keys, and service account keys on a schedule (90 days or less).
- **Scan for leaked secrets** — Run secret detection tools (Gitleaks, TruffleHog, detect-secrets) in pre-commit hooks and CI pipelines.

### CICD-SEC-07 — Insecure System Configuration

- **Harden CI/CD servers** — Apply CIS benchmarks to Jenkins, GitLab, TeamCity instances. Keep them patched and updated.
- **Restrict network access** — CI/CD systems should not be publicly accessible. Use VPN, IP allowlists, or private networking.
- **Disable unnecessary plugins** — Each plugin is an attack surface. Remove plugins that are not actively used.

### CICD-SEC-08 — Ungoverned Third-Party Services

- **Review third-party CI/CD integrations** — GitHub Apps, marketplace actions, and webhooks have access to code and secrets. Audit their permissions regularly.
- **Pin third-party actions to commit SHAs** — Never reference GitHub Actions by mutable tags. Pin to full commit SHA for supply chain integrity.

```yaml
# ❌ INSECURE — mutable tag
- uses: actions/checkout@v4

# ✅ SECURE — pinned to commit SHA
- uses: actions/checkout@b4ffde65f46336ab88eb53be808477a3936bae11 # v4.1.1
```

### CICD-SEC-09 — Improper Artifact Integrity Validation

- **Sign build artifacts** — Sign container images, packages, and binaries. Use Sigstore/Cosign for container images, GPG for packages.
- **Verify artifact provenance** — Use SLSA framework levels to ensure artifacts are built from expected source code by expected build systems.
- **Generate and publish SBOMs** — Create Software Bill of Materials for every release artifact.

### CICD-SEC-10 — Insufficient Logging and Visibility

- **Log all CI/CD events** — Pipeline executions, secret access, configuration changes, user logins, and permission modifications.
- **Centralize CI/CD logs** — Forward all CI/CD logs to your SIEM alongside application and infrastructure logs.
- **Alert on anomalies** — Detect: pipeline runs at unusual times, unexpected secret access, pipeline configuration changes, new admin users.

---

## Section 5 — IaC Templates (Terraform, CloudFormation, Pulumi)

### Universal IaC rules

- **Never hardcode secrets in IaC files** — Use variables referencing secret managers. Never commit `.tfvars` files with secrets.
- **Enable state encryption** — Terraform state files contain sensitive data. Use encrypted remote backends (S3 + KMS, GCS + CMEK, Azure Blob + encryption).
- **Lock state files** — Use state locking (DynamoDB for S3, built-in for GCS/Azure) to prevent concurrent modifications and corruption.
- **Scan IaC for misconfigurations** — Integrate Checkov, tfsec, KICS, or Terrascan into CI/CD to catch security issues before apply.
- **Use modules from trusted sources** — Pin Terraform module versions. Prefer official provider modules. Review third-party modules before use.
- **Apply least privilege to IaC service accounts** — The identity running `terraform apply` must have only the permissions needed for the managed resources, not admin/root.
- **Tag all resources** — Every resource must be tagged with `environment`, `owner`, `managed-by: terraform`, and `cost-center` at minimum. This enables auditing and accountability.
- **Enable drift detection** — Regularly run `terraform plan` to detect manual changes (drift) from the declared state.

### Terraform-specific rules

- **Use `prevent_destroy` on critical resources** — Protect databases, encryption keys, and storage buckets from accidental deletion.
- **Default to encryption** — Every storage resource (S3, RDS, EBS, GCS) must have encryption enabled. Set this as default in modules.
- **Block public access by default** — S3 buckets, storage accounts, and database instances must default to private access. Public access requires explicit override and justification.
- **Use `checkov` or `tfsec` as pre-commit hooks** — Catch misconfigurations before they enter version control.

```hcl
# ❌ INSECURE — multiple violations
resource "aws_s3_bucket" "data" {
  bucket = "my-data-bucket"
}

resource "aws_db_instance" "main" {
  engine         = "postgres"
  instance_class = "db.t3.micro"
  username       = "admin"
  password       = "SuperSecret123!"  # Hardcoded secret!
  publicly_accessible = true           # Public database!
}

# ✅ SECURE — hardened Terraform
resource "aws_s3_bucket" "data" {
  bucket = "my-data-bucket"

  tags = {
    Environment = var.environment
    ManagedBy   = "terraform"
    Owner       = var.team
  }

  lifecycle {
    prevent_destroy = true
  }
}

resource "aws_s3_bucket_public_access_block" "data" {
  bucket = aws_s3_bucket.data.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_server_side_encryption_configuration" "data" {
  bucket = aws_s3_bucket.data.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = aws_kms_key.data.arn
    }
    bucket_key_enabled = true
  }
}

resource "aws_db_instance" "main" {
  engine                  = "postgres"
  instance_class          = "db.t3.micro"
  username                = "admin"
  password                = data.aws_secretsmanager_secret_version.db_password.secret_string
  publicly_accessible     = false
  storage_encrypted       = true
  kms_key_id              = aws_kms_key.db.arn
  deletion_protection     = true
  backup_retention_period = 30
  multi_az                = true

  vpc_security_group_ids = [aws_security_group.db.id]
  db_subnet_group_name   = aws_db_subnet_group.private.name

  tags = {
    Environment = var.environment
    ManagedBy   = "terraform"
  }
}
```

### CloudFormation-specific rules

- **Use `DeletionPolicy: Retain`** — On databases, encryption keys, and S3 buckets.
- **Use `AWS::SecretsManager::Secret`** — Reference secrets from Secrets Manager, not inline parameters.
- **Enable termination protection on stacks** — Prevent accidental deletion of production stacks.
- **Use `cfn-lint` and `cfn_nag`** — Scan CloudFormation templates before deployment.

### Pulumi-specific rules

- **Use Pulumi ESC for secrets** — Never store secrets in Pulumi config as plaintext. Use `pulumi config set --secret`.
- **Enable state encryption** — Configure encrypted backend for Pulumi state.
- **Apply same hardening as Terraform** — All resource-level rules (encryption, private access, tagging) apply equally.

---

## Section 6 — Cloud Provider Hardening (AWS/Azure/GCP)

### Cross-cloud universal rules

- **Enable cloud audit logging** — AWS CloudTrail, Azure Activity Log, GCP Cloud Audit Logs must be enabled for all accounts/projects, with logs sent to a protected, centralized bucket.
- **Use IAM least privilege** — No inline policies with `*` actions or `*` resources. Use managed policies with scoped permissions.
- **Enable MFA on all human accounts** — Enforce MFA for console and CLI access. Use hardware security keys for admin accounts.
- **Block public access by default** — Apply account-wide public access blocks (S3 Block Public Access, Azure Storage deny public access, GCP uniform bucket-level access).
- **Encrypt everything** — Enable default encryption with customer-managed keys (CMKs) for all storage services, databases, and message queues.
- **Restrict network exposure** — Security groups and firewall rules must default to deny-all. Never allow `0.0.0.0/0` on management ports (SSH/22, RDP/3389, database ports).
- **Use VPC/VNet for all resources** — No resources on the public internet unless explicitly required (load balancers, CDNs). Databases, caches, and internal services must be in private subnets.
- **Enable GuardDuty/Defender/SCC** — Use cloud-native threat detection services: AWS GuardDuty, Azure Defender for Cloud, GCP Security Command Center.
- **Enforce tagging policies** — Use SCPs (AWS), Azure Policy, or GCP Organization Policies to enforce mandatory tags on all resources.

### AWS-specific rules

- **Use AWS Organizations with SCPs** — Apply Service Control Policies to prevent dangerous actions (disabling CloudTrail, making S3 buckets public, creating unencrypted resources).
- **Restrict root account usage** — The root account must only be used for initial setup and break-glass scenarios. Enable MFA, do not create access keys.
- **Use VPC endpoints for AWS services** — Access S3, DynamoDB, SQS, etc. via VPC endpoints (PrivateLink) to avoid traffic over the public internet.
- **Enable EBS default encryption** — Configure account-level default EBS encryption for all new volumes.

```hcl
# ✅ SECURE — AWS SCP blocking dangerous actions
resource "aws_organizations_policy" "security_guardrails" {
  name = "security-guardrails"
  content = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "DenyDisablingCloudTrail"
        Effect = "Deny"
        Action = [
          "cloudtrail:StopLogging",
          "cloudtrail:DeleteTrail"
        ]
        Resource = "*"
      },
      {
        Sid    = "DenyPublicS3"
        Effect = "Deny"
        Action = "s3:PutBucketPolicy"
        Resource = "*"
        Condition = {
          StringEquals = {
            "s3:x-amz-acl" = ["public-read", "public-read-write"]
          }
        }
      },
      {
        Sid    = "DenyUnencryptedUploads"
        Effect = "Deny"
        Action = "s3:PutObject"
        Resource = "*"
        Condition = {
          StringNotEquals = {
            "s3:x-amz-server-side-encryption" = "aws:kms"
          }
        }
      }
    ]
  })
}
```

### Azure-specific rules

- **Use Azure Policy for governance** — Enforce encryption, network isolation, and tagging across all subscriptions.
- **Enable Defender for Cloud** — Activate all Defender plans for servers, containers, databases, and Key Vault.
- **Use Managed Identities** — Prefer managed identities over service principal secrets for Azure resource access.
- **Restrict NSG rules** — No inbound rules from `*` (any source) to management or database ports.

### GCP-specific rules

- **Use Organization Policies** — Enforce constraints: `compute.disableSerialPortAccess`, `iam.disableServiceAccountCreation` (except for approved projects), `storage.uniformBucketLevelAccess`.
- **Enable VPC Service Controls** — Create service perimeters around sensitive projects to prevent data exfiltration.
- **Use Workload Identity Federation** — Avoid service account key files. Use workload identity for GKE and OIDC federation for external workloads.
- **Enable Security Command Center Premium** — For threat detection, vulnerability scanning, and compliance monitoring.

---

## Section 7 — Scanning & Compliance Tools Reference

### Recommended tools by category

| Category                 | Tools                                                       |
| ------------------------ | ----------------------------------------------------------- |
| Container image scanning | Trivy, Grype, Snyk Container, Docker Scout                  |
| IaC scanning             | Checkov, tfsec/Trivy, KICS, Terrascan, cfn_nag              |
| Secret detection         | Gitleaks, TruffleHog, detect-secrets, git-secrets           |
| Kubernetes security      | Kubescape, kube-bench (CIS), Kyverno, OPA/Gatekeeper, Falco |
| Dependency scanning      | Dependabot, Renovate, npm audit, pip-audit, cargo audit     |
| CI/CD security           | StepSecurity (harden-runner), Scorecard, Legitify           |
| Cloud posture            | Prowler (AWS), ScoutSuite, CloudSploit, Steampipe           |
| Image signing            | Cosign (Sigstore), Notation, Docker Content Trust           |

### Minimum CI/CD security pipeline

```yaml
# ✅ SECURE — comprehensive security scanning pipeline
name: Security Checks
on: [pull_request]

permissions:
  contents: read
  security-events: write

jobs:
  secrets-scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@<pinned-sha>
        with:
          fetch-depth: 0
      - uses: gitleaks/gitleaks-action@<pinned-sha>

  iac-scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@<pinned-sha>
      - uses: bridgecrewio/checkov-action@<pinned-sha>
        with:
          directory: ./terraform
          framework: terraform

  dependency-scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@<pinned-sha>
      - run: npm audit --audit-level=high
      - run: pip-audit -r requirements.txt

  container-scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@<pinned-sha>
      - run: docker build -t myapp:pr-${{ github.event.pull_request.number }} .
      - uses: aquasecurity/trivy-action@<pinned-sha>
        with:
          image-ref: myapp:pr-${{ github.event.pull_request.number }}
          severity: CRITICAL,HIGH
          exit-code: 1
```

---

## Quick Reference Table

### Container Security Checklist

| Control                 |         Dockerfile          |              Runtime               |            K8s Manifest            |
| ----------------------- | :-------------------------: | :--------------------------------: | :--------------------------------: |
| Non-root user           |       `USER nonroot`        |           `--user 1000`            |        `runAsNonRoot: true`        |
| Read-only filesystem    |             N/A             |           `--read-only`            |   `readOnlyRootFilesystem: true`   |
| Drop capabilities       |             N/A             |          `--cap-drop=ALL`          |     `capabilities.drop: [ALL]`     |
| No privilege escalation |             N/A             | `--security-opt=no-new-privileges` | `allowPrivilegeEscalation: false`  |
| Resource limits         |             N/A             |      `--memory=512m --cpus=1`      |         `resources.limits`         |
| Pinned image            | `FROM image:tag@sha256:...` |                N/A                 |      `image: ...@sha256:...`       |
| Health check            |        `HEALTHCHECK`        |           `--health-cmd`           | `livenessProbe` + `readinessProbe` |
| Seccomp profile         |             N/A             |    `--security-opt seccomp=...`    |  `seccompProfile: RuntimeDefault`  |

### CI/CD Security Checklist (OWASP CI/CD Top 10)

| #   | Risk                        | Key Mitigation                             |
| --- | --------------------------- | ------------------------------------------ |
| 1   | Insufficient Flow Control   | Branch protection + mandatory reviews      |
| 2   | Inadequate IAM              | Least privilege + OIDC federation          |
| 3   | Dependency Chain Abuse      | Lockfiles + private registries + scoping   |
| 4   | Poisoned Pipeline Execution | Protect CI configs + isolate fork builds   |
| 5   | Insufficient PBAC           | Explicit minimal permissions per job       |
| 6   | Credential Hygiene          | No hardcoded secrets + rotation + scanning |
| 7   | Insecure System Config      | Patch CI servers + restrict network + CIS  |
| 8   | Ungoverned 3rd Parties      | Audit integrations + pin to SHA            |
| 9   | Artifact Integrity          | Sign images + verify provenance + SBOM     |
| 10  | Insufficient Logging        | Centralize logs + alert on anomalies       |

### IaC Security Checklist

| Control              |         Terraform         |      CloudFormation      |      Pulumi       |
| -------------------- | :-----------------------: | :----------------------: | :---------------: |
| No hardcoded secrets | `data.aws_secretsmanager` |  `!Ref SecretResource`   | `pulumi.secret()` |
| Encrypted state      |      S3+KMS backend       |      N/A (managed)       | Encrypted backend |
| State locking        |         DynamoDB          |      N/A (managed)       |     Built-in      |
| IaC scanning         |       Checkov/tfsec       |     cfn_nag/cfn-lint     |      Checkov      |
| Pin module versions  |   `version = "~> 3.0"`    |           N/A            |   Pin packages    |
| Prevent destroy      | `prevent_destroy = true`  | `DeletionPolicy: Retain` |  `protect: true`  |

---

## Cross-Reference: IaC ↔ Other Security Files

| IaC Requirement                     | Related Security File                                                                 |
| ----------------------------------- | ------------------------------------------------------------------------------------- |
| Container image dependencies        | `code-security-cwe-top25-2025.md` — CWE-502 Deserialization, CWE-78 Command Injection |
| Secrets in pipelines/manifests      | `code-security-secrets.md` — Vault integration, rotation, Git prevention              |
| API security for K8s services       | `code-security-owasp-api-top10-2023.md` — BOLA, rate limiting                         |
| ASVS verification for deployed apps | `code-security-owasp-asvs-5.0.md` — V12 Secure Communication, V13 Configuration       |
| Privacy in cloud data processing    | `code-security-privacy.md` — Cross-border transfers, data residency                   |

---

## References

- [OWASP Docker Top 10](https://owasp.org/www-project-docker-top-10/)
- [OWASP Kubernetes Top 10](https://owasp.org/www-project-kubernetes-top-ten/)
- [OWASP Top 10 CI/CD Security Risks](https://owasp.org/www-project-top-10-ci-cd-security-risks/)
- [CIS Docker Benchmark v1.8](https://www.cisecurity.org/benchmark/docker)
- [CIS Kubernetes Benchmark](https://www.cisecurity.org/benchmark/kubernetes)
- [NSA/CISA Kubernetes Hardening Guide v1.2](https://media.defense.gov/2022/Aug/29/2003066362/-1/-1/0/CTR_KUBERNETES_HARDENING_GUIDANCE_1.2_20220829.PDF)
- [Kubernetes Pod Security Standards](https://kubernetes.io/docs/concepts/security/pod-security-standards/)
- [SLSA Framework](https://slsa.dev/)
- [Sigstore/Cosign](https://docs.sigstore.dev/)
- [Terraform Security Best Practices](https://developer.hashicorp.com/terraform/cloud-docs/recommended-practices)

---

## License

This file is released under [CC BY-SA 4.0](https://creativecommons.org/licenses/by-sa/4.0/). Based on open-source frameworks from the OWASP Foundation, CIS, NSA/CISA, and the CNCF community.
