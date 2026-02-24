# 🛡️ AI Security Rules

> Comprehensive, OWASP-based security rules for AI-assisted development. Works with Claude Code, Gemini Antigravity, Cursor, and other AI coding assistants.

A curated collection of **820+ security rules** derived from official OWASP, CWE/MITRE, NIST, CIS, NSA/CISA, and global privacy standards, designed to be placed in your AI coding assistant's rules directory. When active, your AI assistant will automatically enforce security best practices while writing, reviewing, or refactoring code.

---

## 📁 Rules Collection

| File                                                                             | Standard                                       | Domain                           |     Lines |    Rules |
| -------------------------------------------------------------------------------- | ---------------------------------------------- | -------------------------------- | --------: | -------: |
| [`code-security-owasp-top10-2025.md`](code-security-owasp-top10-2025.md)         | OWASP Top 10:2025                              | Web Applications                 |       308 |      ~78 |
| [`code-security-owasp-api-top10-2023.md`](code-security-owasp-api-top10-2023.md) | OWASP API Security Top 10:2023                 | APIs & Microservices             |       716 |      ~71 |
| [`code-security-owasp-llm-top10-2025.md`](code-security-owasp-llm-top10-2025.md) | OWASP Top 10 for LLM:2025                      | AI/LLM Applications              |       787 |      ~75 |
| [`code-security-owasp-asvs-5.0.md`](code-security-owasp-asvs-5.0.md)             | OWASP ASVS 5.0                                 | Verification Standard (L1/L2/L3) |       506 |     ~118 |
| [`code-security-mobile.md`](code-security-mobile.md)                             | OWASP Mobile Top 10:2024 + MASVS 2.1           | Mobile (Android & iOS)           |       511 |      ~61 |
| [`code-security-secrets.md`](code-security-secrets.md)                           | Industry Best Practices                        | Secrets Management               |       684 |      ~60 |
| [`code-security-iac.md`](code-security-iac.md)                                   | OWASP Docker/K8s/CI-CD Top 10 + CIS + NSA/CISA | Infrastructure as Code           |       856 |     ~134 |
| [`code-security-cwe-top25-2025.md`](code-security-cwe-top25-2025.md)             | CWE Top 25:2025 (MITRE/CISA)                   | Code-Level Bug Patterns          |       864 |     ~103 |
| [`code-security-privacy.md`](code-security-privacy.md)                           | NIST PF + GDPR/LGPD/CCPA/APPI/PIPEDA/POPIA     | Privacy Engineering              |       782 |     ~120 |
|                                                                                  |                                                | **Total**                        | **6,014** | **~820** |

---

## 🚀 Quick Start

### 1. Clone the repository

```bash
git clone https://github.com/YOUR_USERNAME/ai-security-rules.git
```

### 2. Copy rules to your project

Choose the setup for your AI coding assistant:

---

#### Claude Code

Claude Code automatically reads all `.md` files inside `.claude/rules/` and applies them as system instructions to every interaction. No extra configuration needed.

```bash
mkdir -p .claude/rules/
cp ai-security-rules/code-security-*.md .claude/rules/
```

That's it — Claude will enforce the rules automatically.

---

#### Gemini Antigravity

Antigravity has three mechanisms for custom instructions. For security rules, the recommended approach is a **hybrid setup** using **Rules** (always-on) for critical files and **Skills** (on-demand) for specialized files. This prevents context window bloat while keeping core protections always active.

**Why hybrid?** Rules are injected into every interaction (like a system prompt), so loading 500+ rules at once wastes context and can dilute the agent's focus. Skills are loaded only when relevant, keeping the context lean.

##### Step 1 — Core rules (always active)

Place the most critical security files as **Workspace Rules** in `.agent/rules/`. These are always active regardless of what task you ask the agent to do.

```bash
mkdir -p .agent/rules/
# Core rules — always on
cp ai-security-rules/code-security-owasp-top10-2025.md .agent/rules/
cp ai-security-rules/code-security-secrets.md .agent/rules/
```

> Antigravity also supports a global rules file at `~/.gemini/GEMINI.md` that applies to all projects. You can add cross-project security policies there.

##### Step 2 — Specialized rules (on-demand Skills)

Create **Skills** for domain-specific rules. Each skill lives in its own directory with a `SKILL.md` file. Antigravity only loads a skill when the agent determines it is relevant to the current task.

```bash
# API Security skill
mkdir -p .agent/skills/security-api/
cat > .agent/skills/security-api/SKILL.md << 'SKILLEOF'
---
name: OWASP API Security
description: >
  Security rules for REST/GraphQL API development based on OWASP API Security
  Top 10:2023. Activate when creating, modifying, or reviewing API endpoints,
  middleware, controllers, route handlers, authentication flows, or rate limiting.
---
SKILLEOF
cp ai-security-rules/code-security-owasp-api-top10-2023.md .agent/skills/security-api/rules.md

# LLM Security skill
mkdir -p .agent/skills/security-llm/
cat > .agent/skills/security-llm/SKILL.md << 'SKILLEOF'
---
name: OWASP LLM Security
description: >
  Security rules for LLM-powered applications based on OWASP Top 10 for
  LLM:2025. Activate when working with prompts, RAG pipelines, AI agents,
  model integrations, embedding generation, or LLM API calls.
---
SKILLEOF
cp ai-security-rules/code-security-owasp-llm-top10-2025.md .agent/skills/security-llm/rules.md

# Mobile Security skill
mkdir -p .agent/skills/security-mobile/
cat > .agent/skills/security-mobile/SKILL.md << 'SKILLEOF'
---
name: OWASP Mobile Security
description: >
  Security rules for Android and iOS development based on OWASP Mobile Top 10:2024
  and MASVS 2.1. Activate when working with mobile apps, Kotlin, Swift, React Native,
  Flutter, biometrics, Keychain, Keystore, or mobile platform APIs.
---
SKILLEOF
cp ai-security-rules/code-security-mobile.md .agent/skills/security-mobile/rules.md

# ASVS Verification skill
mkdir -p .agent/skills/security-asvs/
cat > .agent/skills/security-asvs/SKILL.md << 'SKILLEOF'
---
name: OWASP ASVS Verification
description: >
  Comprehensive application security verification rules based on OWASP ASVS 5.0
  (L1/L2/L3). Activate when performing security reviews, compliance checks,
  authentication/authorization audits, or when the user mentions ASVS, security
  levels, or verification requirements.
---
SKILLEOF
cp ai-security-rules/code-security-owasp-asvs-5.0.md .agent/skills/security-asvs/rules.md

# Infrastructure as Code skill
mkdir -p .agent/skills/security-iac/
cat > .agent/skills/security-iac/SKILL.md << 'SKILLEOF'
---
name: Infrastructure as Code Security
description: >
  Security rules for IaC and DevOps based on OWASP Docker/Kubernetes/CI-CD Top 10,
  CIS Benchmarks, and NSA/CISA Kubernetes Hardening Guide. Activate when working
  with Dockerfiles, docker-compose, Kubernetes manifests, Helm charts, Terraform,
  CloudFormation, Pulumi, CI/CD pipelines (GitHub Actions, GitLab CI, Jenkins),
  or cloud provider configuration (AWS, Azure, GCP).
---
SKILLEOF
cp ai-security-rules/code-security-iac.md .agent/skills/security-iac/rules.md

# CWE Top 25 skill
mkdir -p .agent/skills/security-cwe/
cat > .agent/skills/security-cwe/SKILL.md << 'SKILLEOF'
---
name: CWE Top 25 Code-Level Security
description: >
  Code-level bug pattern rules based on CWE Top 25:2025 (MITRE/CISA). Activate
  when writing or reviewing C, C++, or any code involving memory management,
  buffer operations, serialization, file I/O, input validation, or when the user
  mentions CWE, CVE, buffer overflow, use-after-free, or memory safety.
---
SKILLEOF
cp ai-security-rules/code-security-cwe-top25-2025.md .agent/skills/security-cwe/rules.md

# Privacy Engineering skill
mkdir -p .agent/skills/security-privacy/
cat > .agent/skills/security-privacy/SKILL.md << 'SKILLEOF'
---
name: Privacy Engineering (GDPR/LGPD/CCPA/APPI/PIPEDA/POPIA)
description: >
  Privacy-as-code rules based on NIST Privacy Framework and global privacy
  regulations. Activate when working with personal data, consent management,
  user registration, data subject requests, cookie banners, data retention,
  cross-border transfers, breach notification, GDPR, LGPD, CCPA, APPI,
  PIPEDA, POPIA, or any privacy-related feature.
---
SKILLEOF
cp ai-security-rules/code-security-privacy.md .agent/skills/security-privacy/rules.md
```

##### Resulting project structure

```
your-project/
├── .agent/
│   ├── rules/                              # ← Always active
│   │   ├── code-security-owasp-top10-2025.md
│   │   └── code-security-secrets.md
│   └── skills/                             # ← Loaded on-demand
│       ├── security-api/
│       │   ├── SKILL.md                    #   (skill metadata)
│       │   └── rules.md                    #   (actual rules)
│       ├── security-llm/
│       │   ├── SKILL.md
│       │   └── rules.md
│       ├── security-mobile/
│       │   ├── SKILL.md
│       │   └── rules.md
│       ├── security-asvs/
│       │   ├── SKILL.md
│       │   └── rules.md
│       ├── security-iac/
│       │   ├── SKILL.md
│       │   └── rules.md
│       ├── security-cwe/
│       │   ├── SKILL.md
│       │   └── rules.md
│       └── security-privacy/
│           ├── SKILL.md
│           └── rules.md
```

##### Alternative: simple setup (all as Rules)

If you prefer simplicity over context optimization, you can place all files directly in `.agent/rules/`:

```bash
mkdir -p .agent/rules/
cp ai-security-rules/code-security-*.md .agent/rules/
```

This works but loads all 820+ rules into every interaction, which may consume significant context window space.

---

#### Cursor

```bash
mkdir -p .cursor/rules/
cp ai-security-rules/code-security-*.md .cursor/rules/
```

Cursor reads all rule files from `.cursor/rules/` automatically.

---

#### Other AI assistants

Most AI coding assistants support a rules or instructions directory. Copy the `.md` files to wherever your tool reads custom instructions from. The files are plain markdown — universally compatible.

### 3. Choose which rules to include

You don't need all of them. Pick the files relevant to your project:

| If your project is...              | Use these files                                         |
| ---------------------------------- | ------------------------------------------------------- |
| A web application                  | `owasp-top10-2025` + `secrets`                          |
| A REST/GraphQL API                 | `owasp-api-top10-2023` + `secrets`                      |
| An LLM-powered app                 | `owasp-llm-top10-2025` + `secrets`                      |
| A mobile app                       | `mobile` + `secrets`                                    |
| A full-stack app                   | `owasp-top10-2025` + `owasp-api-top10-2023` + `secrets` |
| C/C++ native code                  | `cwe-top25-2025` + `secrets` + `iac`                    |
| Any project handling personal data | `privacy` + relevant security files above               |
| Containerized / Kubernetes         | `iac` + `secrets` + relevant app security file          |
| Regulated / high-security          | All of the above + `owasp-asvs-5.0` + `cwe-top25-2025`  |

### 4. Understand loading strategies

Depending on your AI assistant, rules can be loaded in different ways:

| Strategy                      |   Claude Code    |       Antigravity        |      Cursor      | When to use                        |
| ----------------------------- | :--------------: | :----------------------: | :--------------: | ---------------------------------- |
| **All as Rules** (always-on)  | `.claude/rules/` |     `.agent/rules/`      | `.cursor/rules/` | Small projects, few files selected |
| **Hybrid** (rules + skills)   |       N/A        | Rules + `.agent/skills/` |       N/A        | Recommended for Antigravity        |
| **All as Skills** (on-demand) |       N/A        |     `.agent/skills/`     |       N/A        | Large projects, many rules         |

> **Tip for Antigravity users:** The hybrid approach (core rules always-on + specialized skills on-demand) gives the best balance between security coverage and context efficiency. See the [Antigravity setup section](#gemini-antigravity) above for detailed instructions.

### 5. Configure ASVS level (if using)

If you include the ASVS file, set your target level at the top of the file:

```
TARGET_LEVEL: 2
```

| Level  | For                                                    | Requirements |
| ------ | ------------------------------------------------------ | ------------ |
| **L1** | All applications — baseline controls                   | ~90          |
| **L2** | Most production apps (recommended)                     | ~240         |
| **L3** | Banking, healthcare, military, critical infrastructure | ~350         |

### 6. Start coding

That's it. Your AI assistant will automatically read the rules and enforce them when generating or reviewing code.

---

## 📖 What's Inside Each File

### OWASP Top 10:2025 — Web Applications

Covers the 10 most critical web application security risks: Broken Access Control, Security Misconfiguration, Injection, Cryptographic Failures, and more. Each risk includes mandatory rules with code examples in Python and TypeScript.

### OWASP API Security Top 10:2023 — APIs

Focused on API-specific risks: BOLA, broken authentication, mass assignment, SSRF, rate limiting, and more. Includes middleware patterns, request validation schemas, and defense-in-depth strategies.

### OWASP Top 10 for LLM:2025 — AI Applications

Addresses risks specific to LLM-powered applications: prompt injection, sensitive information disclosure, supply chain security, excessive agency, system prompt leakage, RAG poisoning, and unbounded consumption.

### OWASP ASVS 5.0 — Verification Standard

The most comprehensive file, covering all 17 chapters of the Application Security Verification Standard with a configurable 3-level system (L1/L2/L3). Includes 350+ requirements mapped to specific ASVS IDs for traceability.

### Mobile Security — Android & iOS

Integrates OWASP Mobile Top 10:2024, MASVS 2.1, and MASTG into a unified guide. Covers secure storage, cryptography, authentication, network security, platform interaction, resilience, and privacy with platform-specific examples in Kotlin and Swift.

### Secrets Management

Comprehensive guide for handling secrets: vault integration, rotation policies, Git leak prevention, CI/CD secrets, container secrets, password hashing, encryption keys, log sanitization, and token management.

### Infrastructure as Code (IaC)

Comprehensive IaC security covering 6 layers: **Container Images** (OWASP Docker Top 10, CIS Docker Benchmark), **Container Runtime** (hardened compose, capabilities, seccomp), **Kubernetes** (OWASP K8s Top 10, CIS K8s Benchmark, NSA/CISA Hardening Guide v1.2), **IaC Templates** (Terraform, CloudFormation, Pulumi), **CI/CD Pipelines** (OWASP CI/CD Top 10 — all 10 risks), and **Cloud Provider** (AWS/Azure/GCP hardening with SCPs, policies, and guardrails). Includes scanning tool reference and minimum security pipeline template.

### CWE Top 25:2025 — Code-Level Bug Patterns

Complements OWASP by targeting **specific, concrete software bugs** rather than broad risk categories. Based on real-world CVE/NVD vulnerability data from MITRE/CISA. Organized into 8 categories: Injection & Output Encoding, Memory Safety (C/C++), Authorization & Access Control, File & Resource Handling, Data Integrity & Serialization, Information Exposure, SSRF, and Resource Management. Includes cross-references to OWASP Top 10, language-specific cheat sheets, and compiler hardening flags.

### Privacy Engineering — Global Privacy Regulations

Unified privacy-as-code guide with configurable `TARGET_REGULATIONS` selector. Covers the NIST Privacy Framework 1.1, Privacy by Design/Default principles, and 6 global regulations: GDPR (EU), LGPD (Brazil), CCPA/CPRA (California), APPI (Japan), PIPEDA (Canada), and POPIA (South Africa). Includes: data inventory & classification, consent management, data subject rights (DSR) APIs, retention enforcement, cross-border transfer rules, breach notification workflows, automated decision-making, children's data protection, and AI/ML privacy controls.

---

## 🏗️ Structure

Every file follows a consistent structure:

```
📄 code-security-*.md
├── Metadata (version, source standard, last updated)
├── General Instructions
├── Categorized Sections (one per risk/control)
│   ├── Mandatory Rules (actionable, with references)
│   └── Code Examples (✅ secure / ❌ insecure)
├── Quick Checklist Table
├── References (official sources)
└── License (CC BY-SA 4.0)
```

---

## 🔧 Customization

### Adding project-specific rules

Create additional rule files in your rules directory for project-specific policies:

```markdown
# Project-Specific Security Rules

- All database queries must use the `SafeQuery` wrapper from `@company/db-utils`.
- External API calls must go through the `ApiGateway` service, never directly.
- PII fields must use the `@Encrypted` decorator from `@company/data-protection`.
```

### Combining with other rules

These security rules work alongside other rule files (coding standards, architecture guidelines, style guides). Your AI assistant will apply all rules in the directory together.

---

## 📋 Standards Coverage

| Standard                     | Version                    | Year  | Coverage                      |
| ---------------------------- | -------------------------- | ----- | ----------------------------- |
| OWASP Top 10                 | 2025                       | 2025  | Full (A01–A10)                |
| OWASP API Security Top 10    | 2023                       | 2023  | Full (API1–API10)             |
| OWASP Top 10 for LLM         | 2025                       | 2025  | Full (LLM01–LLM10)            |
| OWASP ASVS                   | 5.0.0                      | 2025  | Full (V1–V17, ~350 reqs)      |
| OWASP Mobile Top 10          | 2024                       | 2024  | Full (M1–M10)                 |
| OWASP MASVS                  | 2.1.0                      | 2024  | Full (8 control groups)       |
| OWASP MASTG                  | Latest                     | 2024+ | Key references                |
| NIST SP 800-63B              | Rev 3                      | 2017  | Auth/session aligned          |
| NIST SP 800-57               | Rev 5                      | 2020  | Key management aligned        |
| OWASP Docker Top 10          | Latest                     | 2024  | Full (D1–D10)                 |
| OWASP Kubernetes Top 10      | 2022 (2025 update pending) | 2022  | Full (K01–K10)                |
| OWASP CI/CD Top 10           | 2022                       | 2022  | Full (CICD-SEC-01–10)         |
| CIS Docker Benchmark         | v1.8                       | 2024  | Key controls                  |
| CIS Kubernetes Benchmark     | Latest                     | 2024  | Key controls                  |
| NSA/CISA K8s Hardening Guide | v1.2                       | 2022  | Aligned                       |
| CWE Top 25                   | 2025                       | 2025  | Full (all 25 weaknesses)      |
| NIST Privacy Framework       | 1.1 IPD                    | 2025  | Core functions aligned        |
| GDPR                         | 2016/679                   | 2016  | Key articles for developers   |
| LGPD                         | 13.709/2018                | 2020  | Key articles for developers   |
| CCPA/CPRA                    | As amended                 | 2023  | Key provisions for developers |
| APPI (Japan)                 | 2022 amended               | 2022  | Key provisions for developers |
| PIPEDA (Canada)              | Federal                    | 2001+ | Key principles for developers |
| POPIA (South Africa)         | Act 4/2013                 | 2021  | Key sections for developers   |

---

## 🤝 Contributing

Contributions are welcome. To add or improve rules:

1. Follow the existing file structure and formatting conventions.
2. Include the source standard reference (e.g., ASVS ID, CWE, MASWE).
3. Provide both secure (✅) and insecure (❌) code examples where applicable.
4. Keep rules actionable — each rule should tell Claude _what to do_, not just what to avoid.

---

## 📄 License

All files in this collection are released under [CC BY-SA 4.0](https://creativecommons.org/licenses/by-sa/4.0/).

Based on the work of the [OWASP Foundation](https://owasp.org/). OWASP standards are open and available under their respective Creative Commons licenses.

---

> **Note:** These rules enhance your AI assistant's security awareness but do not replace professional security audits, penetration testing, or compliance assessments. Always validate critical security controls with qualified security professionals.
