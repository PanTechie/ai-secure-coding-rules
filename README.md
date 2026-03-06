# 🛡️ AI Security Rules

> Comprehensive, OWASP-based security rules for AI-assisted development. Works with Claude Code, Gemini Antigravity, OpenAI Codex, Cursor, and other AI coding assistants.

A curated collection of **1,300+ security rules** across 15 files, derived from official OWASP, CWE/MITRE, NIST, CISA, CIS, NSA/CISA, and global privacy standards. Features a **lightweight always-on essentials file** (271 lines) that enforces critical security patterns automatically, plus **14 detailed skill files** for deep audits and domain-specific guidance. Drop into your project and let your AI write secure code by default.

---

## 📁 Rules Collection

### Always-On Essential Rules

| File | Purpose | Lines | Rules |
| ---- | ------- | ----: | ----: |
| [`standards/security-essentials.md`](standards/security-essentials.md) | **Condensed universal rules — always active** | 219 | ~92 |

This single file contains the most critical security rules extracted from all detailed files below, plus a **Security Review Workflow** — a structured three-step output format for security audits: findings table (severity-sorted with false-positive detection), prompt to select which to fix, and a post-fix status table. It is designed to be active in every interaction without significant context overhead.

### Detailed Security Skills (On-Demand)

These files contain comprehensive rules with code examples, framework-specific patterns, cross-reference tables, and audit checklists. They are loaded **on-demand** — only when the agent determines they are relevant to the current task.

| File | Standard | Domain | Lines | Rules |
| ---- | -------- | ------ | ----: | ----: |
| [`standards/code-security-owasp-top10-2025.md`](standards/code-security-owasp-top10-2025.md) | OWASP Top 10:2025 | Web Applications | 308 | ~78 |
| [`standards/code-security-owasp-api-top10-2023.md`](standards/code-security-owasp-api-top10-2023.md) | OWASP API Security Top 10:2023 | APIs & Microservices | 716 | ~71 |
| [`standards/code-security-owasp-llm-top10-2025.md`](standards/code-security-owasp-llm-top10-2025.md) | OWASP Top 10 for LLM:2025 | AI/LLM Applications | 787 | ~75 |
| [`standards/code-security-owasp-asvs-5.0.md`](standards/code-security-owasp-asvs-5.0.md) | OWASP ASVS 5.0 | Verification Standard (L1/L2/L3) | 506 | ~118 |
| [`standards/code-security-mobile.md`](standards/code-security-mobile.md) | OWASP Mobile Top 10:2024 + MASVS 2.1 | Mobile (Android & iOS) | 511 | ~61 |
| [`standards/code-security-secrets.md`](standards/code-security-secrets.md) | Industry Best Practices | Secrets Management | 684 | ~60 |
| [`standards/code-security-iac.md`](standards/code-security-iac.md) | OWASP Docker/K8s/CI-CD Top 10 + CIS + NSA/CISA | Infrastructure as Code | 856 | ~134 |
| [`standards/code-security-cwe-top25-2025.md`](standards/code-security-cwe-top25-2025.md) | CWE Top 25:2025 (MITRE/CISA) | Code-Level Bug Patterns | 864 | ~103 |
| [`standards/code-security-privacy.md`](standards/code-security-privacy.md) | NIST PF + GDPR/LGPD/CCPA/APPI/PIPEDA/POPIA | Privacy Engineering | 782 | ~120 |
| [`standards/code-security-secure-by-design.md`](standards/code-security-secure-by-design.md) | CISA SbD Principles + Pledge + NIST SSDF | Secure by Design (SbD) | 452 | ~94 |
| [`standards/code-security-python3.md`](standards/code-security-python3.md) | Python Security Advisories + NIST NVD + OWASP | Python 3 & Standard Library | 922 | ~96 |
| [`standards/code-security-php.md`](standards/code-security-php.md) | PHP Security Advisories + NIST NVD + OWASP | PHP 8.x & Standard Extensions | 1,046 | ~110 |
| [`standards/code-security-javascript.md`](standards/code-security-javascript.md) | Node.js Security WG + OWASP + NVD/CVE + Snyk | JavaScript, TypeScript & Node.js 18+ | 674 | ~100 |
| [`standards/code-security-csharp.md`](standards/code-security-csharp.md) | Microsoft Security Advisories + NIST NVD + OWASP | C# / .NET 6+ & ASP.NET Core | 941 | ~105 |
| | | **Total (detailed)** | **10,049** | **~1,325** |

> **Total including essentials:** 15 files, 10,320 lines, ~1,417 rules

---

## 🚀 Quick Start

### Two-Tier Strategy

| Tier | What | How it loads |
| ---- | ---- | ------------ |
| **Essential** (always-on) | `security-essentials.md` — 271 lines, ~92 rules + security review workflow | Loaded on every interaction |
| **Skills** (on-demand) | `code-security-*.md` — full files with examples | Loaded only when relevant |

> **Why two tiers?** The essentials file costs minimal context but covers ~92 critical rules that should always apply. The detailed skill files (6,466 lines total) contain code examples, cross-references, and framework-specific patterns that are most valuable during security reviews and audits, not in every interaction.

---

### Interactive Installer

The fastest way to add security rules to any project — runs interactively, lets you pick the platforms and skills you want, and downloads only what you need.

**Bash (macOS / Linux / WSL):**

```bash
bash <(curl -fsSL https://raw.githubusercontent.com/PanTechie/ai-secure-coding-rules/main/install.sh)
```

**PowerShell (Windows / PowerShell Core):**

```powershell
& ([scriptblock]::Create((irm 'https://raw.githubusercontent.com/PanTechie/ai-secure-coding-rules/main/install.ps1')))
```

> **Note:** Use `bash <(curl ...)` — not `curl ... | bash`. The installer is interactive and needs to read from your terminal. `security-essentials.md` is always included automatically.

The installer will ask you:
1. **Destination directory** — where to install (defaults to current directory)
2. **Platforms** — Claude Code, Gemini Antigravity, Cursor, OpenAI Codex, or all
3. **Skills** — pick any combination of the 13 security domains (or all/none)

---

### Setup by Platform

This repository ships with pre-configured platform directories. **Copy the folder for your platform** to your project root.

---

#### Claude Code

```bash
# Copy the pre-configured setup to your project
cp -r .claude/ /path/to/your-project/

# Or, if your project already has a .claude/ directory, merge:
cp -r .claude/rules/ /path/to/your-project/.claude/
cp -r .claude/skills/ /path/to/your-project/.claude/
```

**What's included:**

```
.claude/
├── rules/
│   └── security-essentials.md     ← always active (271 lines)
└── skills/
    ├── security-web/
    │   ├── SKILL.md                ← trigger: web security reviews, OWASP Top 10
    │   └── rules.md                ← OWASP Top 10:2025 (308 lines)
    ├── security-api/
    │   ├── SKILL.md                ← trigger: API reviews, endpoints, rate limiting
    │   └── rules.md                ← OWASP API Top 10:2023 (716 lines)
    ├── security-llm/
    │   ├── SKILL.md                ← trigger: AI features, RAG, prompt engineering
    │   └── rules.md                ← OWASP LLM Top 10:2025 (787 lines)
    ├── security-asvs/
    │   ├── SKILL.md                ← trigger: compliance, ASVS, verification audits
    │   └── rules.md                ← OWASP ASVS 5.0 (506 lines)
    ├── security-mobile/
    │   ├── SKILL.md                ← trigger: Android/iOS, Kotlin/Swift, mobile apps
    │   └── rules.md                ← Mobile Top 10:2024 + MASVS 2.1 (511 lines)
    ├── security-secrets/
    │   ├── SKILL.md                ← trigger: secrets, API keys, credentials, vaults
    │   └── rules.md                ← Secrets Management (684 lines)
    ├── security-iac/
    │   ├── SKILL.md                ← trigger: Docker, K8s, Terraform, CI/CD, cloud
    │   └── rules.md                ← IaC Security (856 lines)
    ├── security-cwe/
    │   ├── SKILL.md                ← trigger: code audits, CWE, CVE, memory safety
    │   └── rules.md                ← CWE Top 25:2025 (864 lines)
    ├── security-privacy/
    │   ├── SKILL.md                ← trigger: GDPR, LGPD, CCPA, privacy, PII
    │   └── rules.md                ← Privacy Engineering (782 lines)
    ├── security-sbd/
    │   ├── SKILL.md                ← trigger: architecture, secure defaults, CISA
    │   └── rules.md                ← Secure by Design (452 lines)
    ├── security-python3/
    │   ├── SKILL.md                ← trigger: Python 3 code, pickle, subprocess, eval, yaml
    │   └── rules.md                ← Python 3 Security (922 lines)
    ├── security-php/
    │   ├── SKILL.md                ← trigger: PHP code, SQL, XSS, unserialize, sessions
    │   └── rules.md                ← PHP 8.x Security (1,046 lines)
    ├── security-javascript/
    │   ├── SKILL.md                ← trigger: JS/TS code, eval, prototype pollution, DOM XSS, Node.js
    │   └── rules.md                ← JavaScript & TypeScript Security (674 lines)
    └── security-csharp/
        ├── SKILL.md                ← trigger: C#/.NET code, BinaryFormatter, SqlCommand, XmlDocument, ASP.NET Core
        └── rules.md                ← C# / .NET Security (941 lines)
```

---

#### Gemini Antigravity

```bash
cp -r .agent/ /path/to/your-project/
```

**What's included:**

```
.agent/
├── rules/
│   └── security-essentials.md     ← always active (271 lines)
└── skills/
    └── security-{domain}/
        ├── SKILL.md                ← trigger description
        └── rules.md                ← full rules content
```

Same 14-skill structure as Claude Code.

---

#### OpenAI Codex

```bash
cp AGENTS.md /path/to/your-project/
```

`AGENTS.md` at the project root is read by Codex as always-on instructions. It contains the full essentials ruleset (271 lines). For deeper coverage, copy individual files from `standards/` and reference them in your prompts.

---

#### Cursor

```bash
cp -r .cursor/ /path/to/your-project/

# Optional: add detailed files for full coverage
# Note: Cursor requires .mdc extension — rename files after copying
cp standards/code-security-*.md /path/to/your-project/.cursor/rules/
# Then rename each: mv .cursor/rules/file.md .cursor/rules/file.mdc
```

**What's included:**

```
.cursor/
└── rules/
    └── security-essentials.mdc    ← always active (271 lines, alwaysApply: true)
```

---

#### Other AI assistants

Copy `standards/security-essentials.md` to your tool's rules directory. Add detailed files from `standards/` if the tool supports on-demand loading or if context window is not a concern.

---

### Choose which skills to include

You don't need all of them. Pick the files relevant to your project:

| If your project is... | Skills to include |
| --------------------- | ----------------- |
| A web application | `security-web` + `security-secrets` |
| A REST/GraphQL API | `security-api` + `security-secrets` |
| An LLM-powered app | `security-llm` + `security-secrets` |
| A mobile app | `security-mobile` + `security-secrets` |
| A full-stack app | `security-web` + `security-api` + `security-secrets` |
| C/C++ native code | `security-cwe` + `security-secrets` + `security-iac` |
| Python 3 application | `security-python3` + `security-secrets` |
| Python 3 web/API app | `security-python3` + `security-web` + `security-api` + `security-secrets` |
| PHP application | `security-php` + `security-secrets` |
| PHP web/API app | `security-php` + `security-web` + `security-api` + `security-secrets` |
| JavaScript/Node.js application | `security-javascript` + `security-secrets` |
| JavaScript/TypeScript web/API app | `security-javascript` + `security-web` + `security-api` + `security-secrets` |
| C# / .NET application | `security-csharp` + `security-secrets` |
| C# / ASP.NET Core web/API app | `security-csharp` + `security-web` + `security-api` + `security-secrets` |
| Any project handling personal data | `security-privacy` + relevant skills above |
| Containerized / Kubernetes | `security-iac` + `security-secrets` + relevant app skill |
| New product / greenfield project | `security-sbd` + relevant app skills |
| Regulated / high-security | All skills + `security-asvs` + `security-cwe` |

---

## 📁 Repository Structure

```
ai-secure-coding-rules/
│
├── standards/                          ← canonical source files
│   ├── security-essentials.md          ← always-on (271 lines, ~92 rules)
│   └── code-security-*.md             ← 14 detailed skill files
│
├── .claude/                            ← Claude Code (copy to your project)
│   ├── rules/
│   │   └── security-essentials.md
│   └── skills/
│       └── security-{domain}/
│           ├── SKILL.md               ← trigger description
│           └── rules.md               ← full rules content
│
├── .agent/                             ← Gemini Antigravity (copy to your project)
│   ├── rules/
│   │   └── security-essentials.md
│   └── skills/
│       └── security-{domain}/
│           ├── SKILL.md
│           └── rules.md
│
├── .cursor/                            ← Cursor (copy to your project)
│   └── rules/
│       └── security-essentials.mdc    ← .mdc required by Cursor
│
├── AGENTS.md                           ← OpenAI Codex (copy to your project root)
└── README.md
```

---

## 📖 What's Inside Each Skill File

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

Comprehensive IaC security covering 6 layers: **Container Images** (OWASP Docker Top 10, CIS Docker Benchmark), **Container Runtime** (hardened compose, capabilities, seccomp), **Kubernetes** (OWASP K8s Top 10, CIS K8s Benchmark, NSA/CISA Hardening Guide v1.2), **IaC Templates** (Terraform, CloudFormation, Pulumi), **CI/CD Pipelines** (OWASP CI/CD Top 10 — all 10 risks), and **Cloud Provider** (AWS/Azure/GCP hardening with SCPs, policies, and guardrails).

### CWE Top 25:2025 — Code-Level Bug Patterns

Complements OWASP by targeting **specific, concrete software bugs** rather than broad risk categories. Based on real-world CVE/NVD vulnerability data from MITRE/CISA. Organized into 8 categories with cross-references to OWASP Top 10, language-specific cheat sheets, and compiler hardening flags.

### Privacy Engineering — Global Privacy Regulations

Unified privacy-as-code guide with configurable `TARGET_REGULATIONS` selector. Covers the NIST Privacy Framework 1.1, Privacy by Design/Default principles, and 6 global regulations: GDPR (EU), LGPD (Brazil), CCPA/CPRA (California), APPI (Japan), PIPEDA (Canada), and POPIA (South Africa).

### Secure by Design (SbD)

Translates CISA's Secure by Design philosophy into actionable development rules. Covers the **3 CISA Principles**, all **7 CISA Pledge Goals**, and the **NIST SSDF SP 800-218** lifecycle practices. Includes: secure defaults checklist, `security.txt` template, MFA enforcement patterns, SBOM generation, remediation SLAs, and a 25-point architecture review checklist.

### C# / .NET Security

Comprehensive security rules for C# and .NET 6+ applications. Covers 17 vulnerability classes including `BinaryFormatter`/`SoapFormatter` deserialization gadget chains, Newtonsoft.Json `TypeNameHandling` RCE, `DataSet.ReadXml()` (CVE-2020-1147), SQL injection via `FromSqlRaw`, XXE in `XmlDocument`, command injection via `Process.Start`, cryptographic misuse (AES-GCM vs ECB/MD5/DES), path traversal with `Path.Combine`, LDAP injection, ReDoS in `System.Text.RegularExpressions`, TLS bypass in `HttpClient`, SSRF, ASP.NET Core CORS/CSRF/session security, unsafe code / `stackalloc` buffer overflows, open redirect, sensitive data in logs (CVE-2021-34532), and NuGet supply chain. Includes 12 real CVEs (CVSS 5.5–9.8, 2020–2024), a 40-item security checklist, and a tooling table with Roslyn analyzers, Semgrep, and BinSkim.

---

## 🏗️ Skill File Structure

Every detailed file follows a consistent structure:

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

Create additional rule files in your platform's rules directory:

```markdown
# Project-Specific Security Rules

- All database queries must use the `SafeQuery` wrapper from `@company/db-utils`.
- External API calls must go through the `ApiGateway` service, never directly.
- PII fields must use the `@Encrypted` decorator from `@company/data-protection`.
```

### Configure ASVS level (if using)

If you include the ASVS skill, set your target level at the top of the file:

```
TARGET_LEVEL: 2
```

| Level | For | Requirements |
| ----- | --- | ------------ |
| **L1** | All applications — baseline controls | ~90 |
| **L2** | Most production apps (recommended) | ~240 |
| **L3** | Banking, healthcare, military, critical infrastructure | ~350 |

### Keeping platform files in sync

After updating a file in `standards/`, copy it to the corresponding `rules.md` in all platform skill directories:

```bash
# Example: update the web security skill after editing the source
cp standards/code-security-owasp-top10-2025.md .claude/skills/security-web/rules.md
cp standards/code-security-owasp-top10-2025.md .agent/skills/security-web/rules.md
```

---

## 📋 Standards Coverage

| Standard | Version | Year | Coverage |
| -------- | ------- | ---- | -------- |
| OWASP Top 10 | 2025 | 2025 | Full (A01–A10) |
| OWASP API Security Top 10 | 2023 | 2023 | Full (API1–API10) |
| OWASP Top 10 for LLM | 2025 | 2025 | Full (LLM01–LLM10) |
| OWASP ASVS | 5.0.0 | 2025 | Full (V1–V17, ~350 reqs) |
| OWASP Mobile Top 10 | 2024 | 2024 | Full (M1–M10) |
| OWASP MASVS | 2.1.0 | 2024 | Full (8 control groups) |
| OWASP MASTG | Latest | 2024+ | Key references |
| NIST SP 800-63B | Rev 3 | 2017 | Auth/session aligned |
| NIST SP 800-57 | Rev 5 | 2020 | Key management aligned |
| OWASP Docker Top 10 | Latest | 2024 | Full (D1–D10) |
| OWASP Kubernetes Top 10 | 2022 | 2022 | Full (K01–K10) |
| OWASP CI/CD Top 10 | 2022 | 2022 | Full (CICD-SEC-01–10) |
| CIS Docker Benchmark | v1.8 | 2024 | Key controls |
| CIS Kubernetes Benchmark | Latest | 2024 | Key controls |
| NSA/CISA K8s Hardening Guide | v1.2 | 2022 | Aligned |
| CWE Top 25 | 2025 | 2025 | Full (all 25 weaknesses) |
| CISA Secure by Design | v2 (Oct 2023) | 2023 | Full (3 principles + 7 pledge goals) |
| NIST SP 800-218 (SSDF) | v1.1 / v1.2 draft | 2022/2025 | Full (PO/PS/PW/RV) |
| NIST Privacy Framework | 1.1 IPD | 2025 | Core functions aligned |
| GDPR | 2016/679 | 2016 | Key articles for developers |
| LGPD | 13.709/2018 | 2020 | Key articles for developers |
| CCPA/CPRA | As amended | 2023 | Key provisions for developers |
| APPI (Japan) | 2022 amended | 2022 | Key provisions for developers |
| PIPEDA (Canada) | Federal | 2001+ | Key principles for developers |
| POPIA (South Africa) | Act 4/2013 | 2021 | Key sections for developers |

---

## 🤝 Contributing

Contributions are welcome. To add or improve rules:

1. Follow the existing file structure and formatting conventions in `standards/`.
2. Include the source standard reference (e.g., ASVS ID, CWE, MASWE).
3. Provide both secure (✅) and insecure (❌) code examples where applicable.
4. Keep rules actionable — each rule should tell the AI _what to do_, not just what to avoid.
5. After updating a file in `standards/`, copy it to the corresponding `rules.md` in all platform skill directories.

---

## 📄 License

All files in this collection are released under [CC BY-SA 4.0](https://creativecommons.org/licenses/by-sa/4.0/).

Based on the work of the [OWASP Foundation](https://owasp.org/). OWASP standards are open and available under their respective Creative Commons licenses.

---

> **Note:** These rules enhance your AI assistant's security awareness but do not replace professional security audits, penetration testing, or compliance assessments. Always validate critical security controls with qualified security professionals.
