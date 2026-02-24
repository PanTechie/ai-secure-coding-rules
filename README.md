# 🛡️ AI Security Rules

> Comprehensive, OWASP-based security rules for AI-assisted development. Works with Claude Code, Gemini Antigravity, Cursor, and other AI coding assistants.

A curated collection of **912+ security rules** across 10 files, derived from official OWASP, CWE/MITRE, NIST, CIS, NSA/CISA, and global privacy standards. Features a **lightweight always-on essentials file** (157 lines) that enforces critical security patterns automatically, plus **9 detailed reference files** for deep audits and domain-specific guidance. Drop into your project and let your AI write secure code by default.

---

## 📁 Rules Collection

### Always-On Essential Rules

| File                                               | Purpose                                       | Lines | Rules |
| -------------------------------------------------- | --------------------------------------------- | ----: | ----: |
| [`security-essentials.md`](security-essentials.md) | **Condensed universal rules — always active** |   157 |   ~92 |

This single file contains the most critical security rules extracted from all detailed files below. It is designed to be lightweight enough to remain active in every interaction without significant context overhead.

### Detailed Security Files (Skills / Reference)

These files contain comprehensive rules with code examples, framework-specific patterns, cross-reference tables, and audit checklists. Use them as **on-demand skills** for deep reviews or as **reference documentation**.

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
|                                                                                  |                                                | **Total (detailed)**             | **6,014** | **~820** |

> **Total including essentials:** 10 files, 6,171 lines, ~912 rules

---

## 🚀 Quick Start

### Recommended Setup: Essentials (always-on) + Detailed (on-demand)

The most effective approach is a **two-tier setup**:

1. **`security-essentials.md`** → always-on rule (157 lines, low context cost)
2. **Detailed files** → on-demand skills for audits, reviews, and deep guidance

This way, your AI assistant automatically enforces critical security patterns in every code generation, while detailed rules with examples are available when you need deeper analysis.

### 1. Clone the repository

```bash
git clone https://github.com/YOUR_USERNAME/ai-security-rules.git
```

### 2. Set up your AI assistant

Choose the setup for your AI coding assistant:

---

#### Claude Code

Claude Code reads all `.md` files in `.claude/rules/` as always-on rules and supports `/` commands for skills.

```bash
# Step 1 — Always-on essential rules
mkdir -p .claude/rules/
cp ai-security-rules/security-essentials.md .claude/rules/

# Step 2 — Detailed files as project reference (Claude reads when relevant)
mkdir -p .claude/skills/
cp ai-security-rules/code-security-*.md .claude/skills/
```

With this setup, Claude automatically applies the essential security rules in every interaction. When you need deeper analysis, you can reference the detailed files or ask Claude to review against a specific standard.

**Alternative: all as rules (simpler, heavier context)**

```bash
mkdir -p .claude/rules/
cp ai-security-rules/security-essentials.md .claude/rules/
cp ai-security-rules/code-security-*.md .claude/rules/
```

---

#### Gemini Antigravity

Antigravity supports **Rules** (always-on) and **Skills** (on-demand). The recommended approach places the essentials as a Rule and detailed files as Skills with smart metadata for automatic loading.

##### Step 1 — Essential rules (always active)

```bash
mkdir -p .agent/rules/
cp ai-security-rules/security-essentials.md .agent/rules/
```

##### Step 2 — Detailed rules (on-demand Skills)

Create **Skills** for each detailed file. Antigravity only loads a skill when the agent determines it is relevant to the current task, based on the `description` in `SKILL.md`.

```bash
# Web Application Security skill
mkdir -p .agent/skills/security-web/
cat > .agent/skills/security-web/SKILL.md << 'SKILLEOF'
---
name: OWASP Web Application Security
description: >
  Detailed security rules for web applications based on OWASP Top 10:2025.
  Activate when performing security reviews, audits, or when the user asks
  for in-depth security analysis of web application code, access control,
  authentication, session management, or security headers.
---
SKILLEOF
cp ai-security-rules/code-security-owasp-top10-2025.md .agent/skills/security-web/rules.md

# API Security skill
mkdir -p .agent/skills/security-api/
cat > .agent/skills/security-api/SKILL.md << 'SKILLEOF'
---
name: OWASP API Security
description: >
  Detailed security rules for REST/GraphQL API development based on OWASP API
  Security Top 10:2023. Activate when performing API security reviews, audits,
  or when the user asks for in-depth analysis of API endpoints, middleware,
  authentication flows, or rate limiting.
---
SKILLEOF
cp ai-security-rules/code-security-owasp-api-top10-2023.md .agent/skills/security-api/rules.md

# LLM Security skill
mkdir -p .agent/skills/security-llm/
cat > .agent/skills/security-llm/SKILL.md << 'SKILLEOF'
---
name: OWASP LLM Security
description: >
  Detailed security rules for LLM-powered applications based on OWASP Top 10
  for LLM:2025. Activate when performing security reviews of AI features,
  prompt engineering, RAG pipelines, or AI agent implementations.
---
SKILLEOF
cp ai-security-rules/code-security-owasp-llm-top10-2025.md .agent/skills/security-llm/rules.md

# ASVS Verification skill
mkdir -p .agent/skills/security-asvs/
cat > .agent/skills/security-asvs/SKILL.md << 'SKILLEOF'
---
name: OWASP ASVS Verification
description: >
  Comprehensive verification rules based on OWASP ASVS 5.0 (L1/L2/L3).
  Activate when performing compliance checks, security verification audits,
  or when the user mentions ASVS, security levels, or verification requirements.
---
SKILLEOF
cp ai-security-rules/code-security-owasp-asvs-5.0.md .agent/skills/security-asvs/rules.md

# Mobile Security skill
mkdir -p .agent/skills/security-mobile/
cat > .agent/skills/security-mobile/SKILL.md << 'SKILLEOF'
---
name: OWASP Mobile Security
description: >
  Detailed security rules for Android and iOS based on OWASP Mobile Top 10:2024
  and MASVS 2.1. Activate when performing mobile security reviews, audits, or
  when working with Kotlin, Swift, React Native, Flutter, biometrics, or platform APIs.
---
SKILLEOF
cp ai-security-rules/code-security-mobile.md .agent/skills/security-mobile/rules.md

# Secrets Management skill
mkdir -p .agent/skills/security-secrets/
cat > .agent/skills/security-secrets/SKILL.md << 'SKILLEOF'
---
name: Secrets Management
description: >
  Detailed secrets management rules covering vault integration, rotation,
  Git leak prevention, and CI/CD secrets. Activate when performing secrets
  audits, configuring secret managers, or reviewing credential handling.
---
SKILLEOF
cp ai-security-rules/code-security-secrets.md .agent/skills/security-secrets/rules.md

# Infrastructure as Code skill
mkdir -p .agent/skills/security-iac/
cat > .agent/skills/security-iac/SKILL.md << 'SKILLEOF'
---
name: Infrastructure as Code Security
description: >
  Detailed IaC security rules based on OWASP Docker/Kubernetes/CI-CD Top 10,
  CIS Benchmarks, and NSA/CISA Guide. Activate when performing infrastructure
  security reviews, writing Dockerfiles, K8s manifests, Terraform, CI/CD pipelines,
  or cloud provider configurations.
---
SKILLEOF
cp ai-security-rules/code-security-iac.md .agent/skills/security-iac/rules.md

# CWE Top 25 skill
mkdir -p .agent/skills/security-cwe/
cat > .agent/skills/security-cwe/SKILL.md << 'SKILLEOF'
---
name: CWE Top 25 Code-Level Security
description: >
  Detailed code-level bug pattern rules based on CWE Top 25:2025 (MITRE/CISA).
  Activate when performing code security audits, reviewing C/C++ code, or when
  the user mentions CWE, CVE, buffer overflow, or memory safety.
---
SKILLEOF
cp ai-security-rules/code-security-cwe-top25-2025.md .agent/skills/security-cwe/rules.md

# Privacy Engineering skill
mkdir -p .agent/skills/security-privacy/
cat > .agent/skills/security-privacy/SKILL.md << 'SKILLEOF'
---
name: Privacy Engineering (GDPR/LGPD/CCPA/APPI/PIPEDA/POPIA)
description: >
  Detailed privacy-as-code rules based on NIST Privacy Framework and global
  regulations. Activate when performing privacy reviews, implementing consent
  management, data subject rights, data retention, or when the user mentions
  GDPR, LGPD, CCPA, APPI, PIPEDA, POPIA, or any privacy-related feature.
---
SKILLEOF
cp ai-security-rules/code-security-privacy.md .agent/skills/security-privacy/rules.md
```

##### Resulting project structure

```
your-project/
├── .agent/
│   ├── rules/                              # ← Always active (lightweight)
│   │   └── security-essentials.md          #   157 lines, ~92 rules
│   └── skills/                             # ← Loaded on-demand (detailed)
│       ├── security-web/
│       │   ├── SKILL.md
│       │   └── rules.md
│       ├── security-api/
│       │   ├── SKILL.md
│       │   └── rules.md
│       ├── security-llm/
│       │   ├── SKILL.md
│       │   └── rules.md
│       ├── security-asvs/
│       │   ├── SKILL.md
│       │   └── rules.md
│       ├── security-mobile/
│       │   ├── SKILL.md
│       │   └── rules.md
│       ├── security-secrets/
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

---

#### Cursor

```bash
mkdir -p .cursor/rules/
cp ai-security-rules/security-essentials.md .cursor/rules/
# Optionally, add detailed files for heavier coverage:
# cp ai-security-rules/code-security-*.md .cursor/rules/
```

---

#### Other AI assistants

Copy `security-essentials.md` to your tool's rules directory. Add detailed files if the tool supports on-demand loading or if context window is not a concern.

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

### 4. Understand the two-tier strategy

| Tier                      | What                                 |  Where (Claude)   | Where (Antigravity) |       Where (Cursor)        |
| ------------------------- | ------------------------------------ | :---------------: | :-----------------: | :-------------------------: |
| **Essential** (always-on) | `security-essentials.md` — 157 lines | `.claude/rules/`  |   `.agent/rules/`   |      `.cursor/rules/`       |
| **Detailed** (on-demand)  | `code-security-*.md` — full files    | `.claude/skills/` |  `.agent/skills/`   | `.cursor/rules/` (optional) |

> **Why two tiers?** The essentials file (157 lines) costs minimal context but covers ~92 critical rules that should always apply. The detailed files (6,014 lines total) contain code examples, cross-references, and framework-specific patterns that are most valuable during security reviews and audits, not in every interaction.

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
