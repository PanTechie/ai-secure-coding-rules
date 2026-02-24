# 🛡️ AI Security Rules

> Comprehensive, OWASP-based security rules for AI-assisted development. Works with Claude Code, Gemini Antigravity, Cursor, and other AI coding assistants.

A curated collection of **539+ security rules** derived from official OWASP standards, designed to be placed in your AI coding assistant's rules directory. When active, your AI assistant will automatically enforce security best practices while writing, reviewing, or refactoring code.

---

## 📁 Rules Collection

| File                                                                             | Standard                             | Domain                           |     Lines |    Rules |
| -------------------------------------------------------------------------------- | ------------------------------------ | -------------------------------- | --------: | -------: |
| [`code-security-owasp-top10-2025.md`](code-security-owasp-top10-2025.md)         | OWASP Top 10:2025                    | Web Applications                 |       308 |      ~78 |
| [`code-security-owasp-api-top10-2023.md`](code-security-owasp-api-top10-2023.md) | OWASP API Security Top 10:2023       | APIs & Microservices             |       716 |      ~71 |
| [`code-security-owasp-llm-top10-2025.md`](code-security-owasp-llm-top10-2025.md) | OWASP Top 10 for LLM:2025            | AI/LLM Applications              |       787 |      ~75 |
| [`code-security-owasp-asvs-5.0.md`](code-security-owasp-asvs-5.0.md)             | OWASP ASVS 5.0                       | Verification Standard (L1/L2/L3) |       506 |     ~118 |
| [`code-security-mobile.md`](code-security-mobile.md)                             | OWASP Mobile Top 10:2024 + MASVS 2.1 | Mobile (Android & iOS)           |       511 |      ~61 |
| [`code-security-secrets.md`](code-security-secrets.md)                           | Industry Best Practices              | Secrets Management               |       684 |      ~60 |
| [`code-security-infrastructure.md`](code-security-infrastructure.md)             | Industry Best Practices              | Infrastructure & Cloud           |       689 |      ~76 |
|                                                                                  |                                      | **Total**                        | **4,201** | **~539** |

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

# Infrastructure Security skill
mkdir -p .agent/skills/security-infrastructure/
cat > .agent/skills/security-infrastructure/SKILL.md << 'SKILLEOF'
---
name: Infrastructure & Cloud Security
description: >
  Security rules for infrastructure and cloud environments. Activate when working
  with Docker, Kubernetes, Terraform, CloudFormation, CI/CD pipelines, IAM policies,
  cloud storage, network configuration, or any IaC templates.
---
SKILLEOF
cp ai-security-rules/code-security-infrastructure.md .agent/skills/security-infrastructure/rules.md
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
│       └── security-infrastructure/
│           ├── SKILL.md
│           └── rules.md
```

##### Alternative: simple setup (all as Rules)

If you prefer simplicity over context optimization, you can place all files directly in `.agent/rules/`:

```bash
mkdir -p .agent/rules/
cp ai-security-rules/code-security-*.md .agent/rules/
```

This works but loads all 539+ rules into every interaction, which may consume significant context window space.

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

| If your project is...     | Use these files                                         |
| ------------------------- | ------------------------------------------------------- |
| A web application         | `owasp-top10-2025` + `secrets`                          |
| A REST/GraphQL API        | `owasp-api-top10-2023` + `secrets`                      |
| An LLM-powered app        | `owasp-llm-top10-2025` + `secrets`                      |
| A mobile app              | `mobile` + `secrets`                                    |
| A full-stack app          | `owasp-top10-2025` + `owasp-api-top10-2023` + `secrets` |
| Regulated / high-security | All of the above + `owasp-asvs-5.0` + `infrastructure`  |

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

### Infrastructure & Cloud

Covers IaC security, IAM/least privilege, network segmentation, container hardening, cloud storage, database security, logging/monitoring, CI/CD pipelines, Kubernetes security, and disaster recovery.

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

| Standard                  | Version | Year  | Coverage                 |
| ------------------------- | ------- | ----- | ------------------------ |
| OWASP Top 10              | 2025    | 2025  | Full (A01–A10)           |
| OWASP API Security Top 10 | 2023    | 2023  | Full (API1–API10)        |
| OWASP Top 10 for LLM      | 2025    | 2025  | Full (LLM01–LLM10)       |
| OWASP ASVS                | 5.0.0   | 2025  | Full (V1–V17, ~350 reqs) |
| OWASP Mobile Top 10       | 2024    | 2024  | Full (M1–M10)            |
| OWASP MASVS               | 2.1.0   | 2024  | Full (8 control groups)  |
| OWASP MASTG               | Latest  | 2024+ | Key references           |
| NIST SP 800-63B           | Rev 3   | 2017  | Auth/session aligned     |
| NIST SP 800-57            | Rev 5   | 2020  | Key management aligned   |

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
