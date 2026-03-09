# 🛡️ AI Security Rules

> Comprehensive, OWASP-based security rules for AI-assisted development. Works with Claude Code, Gemini Antigravity, OpenAI Codex, Cursor, and other AI coding assistants.

A curated collection of **3,100+ security rules** across 31 files, derived from official OWASP, CWE/MITRE, NIST, CISA, CIS, NSA/CISA, and global privacy standards. Features a **lightweight always-on essentials file** (271 lines) that enforces critical security patterns automatically, plus **30 detailed skill files** for deep audits and domain-specific guidance. Drop into your project and let your AI write secure code by default.

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
| [`standards/code-security-jvm.md`](standards/code-security-jvm.md) | Oracle Java Security Advisories + Kotlin Security Docs + NIST NVD + Spring Security | Java 11+ & Kotlin 1.9+ on the JVM, Spring Boot | 1,194 | ~127 |
| [`standards/code-security-clojure.md`](standards/code-security-clojure.md) | Clojure Security Advisories + NIST NVD + OWASP Injection Prevention + Ring/Leiningen Security | Clojure 1.11+ on the JVM, Ring/Compojure, next.jdbc | 542 | ~60 |
| [`standards/code-security-ruby.md`](standards/code-security-ruby.md) | Ruby Security Advisories + Rails Security Guide + OWASP + NIST NVD + Snyk Ruby DB | Ruby 3.x & Ruby on Rails 7.x, Sinatra, Devise, Nokogiri | 704 | ~115 |
| [`standards/code-security-elixir.md`](standards/code-security-elixir.md) | Elixir Security Advisories + Erlang/OTP Advisories + NIST NVD + Sobelow + OWASP | Elixir 1.15+ & Phoenix 1.7+, Ecto, Plug, LiveView | 794 | ~120 |
| [`standards/code-security-c-cpp.md`](standards/code-security-c-cpp.md) | SEI CERT C/C++ Coding Standard + MISRA C:2023 + CWE/MITRE + NIST NVD + Google Project Zero | C11/C17 & C++17/C++20, GCC/Clang, OpenSSL, libsodium | 861 | ~130 |
| [`standards/code-security-dart.md`](standards/code-security-dart.md) | Dart SDK Security Advisories + OWASP MASVS + OWASP Mobile Top 10:2024 + NVD + GitHub Advisory Database + Zellic Research | Dart 3.x & Flutter 3.x, mobile (Android/iOS), Dart server, Flutter web | 1,331 | ~150 |
| [`standards/code-security-objc.md`](standards/code-security-objc.md) | Apple Platform Security Guide + OWASP MASVS 2.1 + SEI CERT C + NVD + GitHub Advisory Database + Project Zero / ZecOps | Objective-C and Objective-C++ targeting iOS 14+ and macOS 12+ | 990 | ~140 |
| [`standards/code-security-swift.md`](standards/code-security-swift.md) | Apple Platform Security Guide + OWASP MASVS 2.1 + Swift Evolution + NVD + GitHub Advisory Database + Vapor Security Advisories | Swift 5.x/6.x on iOS 16+/macOS 13+ and server-side (Vapor 4) | 1,012 | ~145 |
| [`standards/code-security-go.md`](standards/code-security-go.md) | Go Security Policy + OWASP Top 10:2025 + CWE/MITRE + NVD + Go Vulnerability Database + CNCF Security Whitepaper | Go 1.21+ web services, microservices, CLIs, and cloud-native (net/http, gin, echo, gRPC, GORM) | 1,153 | ~155 |
| [`standards/code-security-rust.md`](standards/code-security-rust.md) | Rust Security Advisory Database (RustSec) + OWASP Top 10:2025 + CWE/MITRE + NVD + GitHub Advisory Database + Rust Secure Code Working Group | Rust 1.70+ web services, CLIs, embedded systems (axum, actix-web, diesel, sqlx, ring, rustls, reqwest) | 737 | ~130 |
| [`standards/code-security-react.md`](standards/code-security-react.md) | React Security Documentation + OWASP Top 10:2025 + CWE/MITRE + NVD + GitHub Advisory Database + Snyk React Security Advisories | React 18+ / React 19 SPAs, SSR, and Server Components (Redux, Zustand, react-router, React Query, Vite) | 764 | ~110 |
| [`standards/code-security-nextjs.md`](standards/code-security-nextjs.md) | Next.js Security Documentation + Vercel Security Advisories + OWASP Top 10:2025 + CWE/MITRE + NVD + Auth.js Security Advisories | Next.js 14+ App Router (Server Components, Server Actions, Route Handlers, Middleware) and Pages Router | 826 | ~120 |
| [`standards/code-security-angular.md`](standards/code-security-angular.md) | Angular Security Documentation + OWASP Top 10:2025 + CWE/MITRE + NVD + GitHub Advisory Database + Angular CDK/Material Security Advisories | Angular 15+ SPAs, SSR (Universal), and PWAs (NgRx, RxJS, angular-oauth2-oidc, HttpClient, Service Workers) | 758 | ~110 |
| [`standards/code-security-vue.md`](standards/code-security-vue.md) | Vue.js Security Guide + Nuxt Security Module Docs + OWASP Top 10:2025 + CWE/MITRE + NVD + GitHub Advisory Database + Snyk Vue Security Advisories | Vue 3.x / Nuxt 3.x SPAs, SSR, and PWAs (Pinia, Vue Router, Vite, vue-i18n, nuxt-security) | 849 | ~120 |
| | | **Total (detailed)** | **22,564** | **~3,057** |

> **Total including essentials:** 31 files, 22,835 lines, ~3,149 rules

---

## 🚀 Quick Start

### Two-Tier Strategy

| Tier | What | How it loads |
| ---- | ---- | ------------ |
| **Essential** (always-on) | `security-essentials.md` — 271 lines, ~92 rules + security review workflow | Loaded on every interaction |
| **Skills** (on-demand) | `code-security-*.md` — full files with examples | Loaded only when relevant |

> **Why two tiers?** The essentials file costs minimal context but covers ~92 critical rules that should always apply. The detailed skill files (6,466 lines total) contain code examples, cross-references, and framework-specific patterns that are most valuable during security reviews and audits, not in every interaction.

---

### VSCode Extension

The easiest way to install if you use Visual Studio Code. Search for **"AI Secure Coding Rules"** in the Extensions panel, or install from the Marketplace.

#### First install

1. Open your project folder in VSCode
2. Press `Ctrl+Shift+P` (Windows/Linux) or `Cmd+Shift+P` (Mac)
3. Type `AI Secure Coding` and select **`Install AI Secure Coding Rules`**
4. **Step 1 — Platforms:** select one or more AI assistants to install for:
   - `Claude Code` → files go into `.claude/`
   - `Gemini Antigravity` → files go into `.agent/`
   - `Cursor` → files go into `.cursor/`
   - `OpenAI Codex` → creates `AGENTS.md`
5. **Step 2 — Skills:** pick the security domains you want (or choose *All skills* / *None*). `security-essentials` is always included.
6. A progress notification shows each file being downloaded. When done, commit the result:

```bash
git add .claude/ .agent/ .cursor/ AGENTS.md .ai-secure-rules.json
git commit -m "chore: add AI secure coding rules"
```

#### Checking for updates / managing installed skills

After the first install, use **`Manage AI Secure Coding Rules`** (`Ctrl+Shift+P` → `AI Secure Coding: Manage`):

1. The extension fetches current file hashes from GitHub (one API call)
2. A list shows all 29 skills with their status:
   - `✓ Up-to-date` — already on the latest version
   - `↑ Update available` — newer version on GitHub (pre-selected automatically)
   - `? Installed (version unknown)` — installed via shell script, version not tracked
   - `⊘ Not installed`
3. Select the skills you want to act on, then choose:
   - **Install / Update** → select platforms → downloads latest files
   - **Remove** → deletes skill files from the workspace

A `.ai-secure-rules.json` manifest is written to the workspace root to track installed platforms and skill versions across sessions.

> Source: [`vscode-extension/`](vscode-extension/)

---

### Interactive Installer (Terminal)

For non-VSCode environments (terminal, CI/CD, remote servers). Runs interactively, lets you pick the platforms and skills you want, and downloads only what you need.

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
3. **Skills** — pick any combination of the 16 security domains (or all/none)

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
    ├── security-csharp/
    │   ├── SKILL.md                ← trigger: C#/.NET code, BinaryFormatter, SqlCommand, XmlDocument, ASP.NET Core
    │   └── rules.md                ← C# / .NET Security (941 lines)
    ├── security-jvm/
    │   ├── SKILL.md                ← trigger: Java/Kotlin code, ObjectInputStream, JNDI, SpEL, Log4Shell, coroutines
    │   └── rules.md                ← Java & Kotlin JVM Security (1,148 lines)
    ├── security-clojure/
    │   ├── SKILL.md                ← trigger: Clojure code, eval, read-string, nREPL, Ring, next.jdbc, nippy
    │   └── rules.md                ← Clojure Security (542 lines)
    ├── security-ruby/
    │   ├── SKILL.md                ← trigger: Ruby/Rails code, eval, Marshal.load, YAML.load, params.permit!, html_safe, Brakeman
    │   └── rules.md                ← Ruby & Rails Security (704 lines)
    ├── security-elixir/
    │   ├── SKILL.md                ← trigger: Elixir/Phoenix code, Code.eval_string, String.to_atom, binary_to_term, Sobelow
    │   └── rules.md                ← Elixir & Phoenix Security (794 lines)
    ├── security-c-cpp/
    │   ├── SKILL.md                ← trigger: C/C++ code, gets/strcpy, malloc/free, use-after-free, format string, ASan
    │   └── rules.md                ← C / C++ Security (861 lines)
    ├── security-dart/
    │   ├── SKILL.md                ← trigger: Dart/Flutter code, Random(), SharedPreferences, badCertificateCallback, sqflite, dart:ffi
    │   └── rules.md                ← Dart & Flutter Security (1,331 lines)
    ├── security-objc/
    │   ├── SKILL.md                ← trigger: Objective-C code, NSKeyedUnarchiver, KVC injection, NSLog, performSelector:, CocoaPods
    │   └── rules.md                ← Objective-C Security (990 lines)
    ├── security-swift/
    │   ├── SKILL.md                ← trigger: Swift/Vapor code, force-unwrap, Codable, UnsafePointer, actor, CryptoKit, Leaf, SPM
    │   └── rules.md                ← Swift Security (1,012 lines)
    ├── security-go/
    │   ├── SKILL.md                ← trigger: Go code, os/exec, database/sql fmt.Sprintf, text/template, goroutine race, govulncheck
    │   └── rules.md                ← Go Security (1,153 lines)
    ├── security-rust/
    │   ├── SKILL.md                ← trigger: Rust code, unsafe, integer overflow, diesel/sqlx, AES-GCM, rustls, cargo-audit, RustSec
    │   └── rules.md                ← Rust Security (737 lines)
    ├── security-react/
    │   ├── SKILL.md                ← trigger: React code, dangerouslySetInnerHTML, javascript: URL, localStorage token, CSP, Server Components
    │   └── rules.md                ← React Security (764 lines)
    ├── security-nextjs/
    │   ├── SKILL.md                ← trigger: Next.js code, middleware bypass, Server Actions, NEXT_PUBLIC_, next-auth, SSRF, ISR cache
    │   └── rules.md                ← Next.js Security (826 lines)
    ├── security-angular/
    │   ├── SKILL.md                ← trigger: Angular code, bypassSecurityTrust*, [innerHTML], CSRF, ReDoS in pipes, NgRx, PKCE, ngCspNonce
    │   └── rules.md                ← Angular Security (758 lines)
    └── security-vue/
        ├── SKILL.md                ← trigger: Vue/Nuxt code, v-html, Vue.compile(), VITE_ leaks, Pinia, useFetch SSRF, nuxt-security
        └── rules.md                ← Vue.js / Nuxt Security (849 lines)
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

Same 29-skill structure as Claude Code.

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
| Java or Kotlin application | `security-jvm` + `security-secrets` |
| Java or Kotlin / Spring Boot web/API app | `security-jvm` + `security-web` + `security-api` + `security-secrets` |
| Clojure application | `security-clojure` + `security-jvm` + `security-secrets` |
| Clojure web/API app (Ring/Compojure) | `security-clojure` + `security-jvm` + `security-web` + `security-api` + `security-secrets` |
| Ruby application | `security-ruby` + `security-secrets` |
| Ruby on Rails web/API app | `security-ruby` + `security-web` + `security-api` + `security-secrets` |
| Elixir application | `security-elixir` + `security-secrets` |
| Elixir / Phoenix web/API app | `security-elixir` + `security-web` + `security-api` + `security-secrets` |
| C / C++ application or library | `security-c-cpp` + `security-secrets` |
| C / C++ network service | `security-c-cpp` + `security-web` + `security-api` + `security-secrets` |
| Dart / Flutter mobile app | `security-dart` + `security-mobile` + `security-secrets` |
| Dart / Flutter web app | `security-dart` + `security-web` + `security-secrets` |
| Dart server-side application | `security-dart` + `security-api` + `security-secrets` |
| Objective-C iOS/macOS app | `security-objc` + `security-mobile` + `security-secrets` |
| Swift iOS/macOS app | `security-swift` + `security-mobile` + `security-secrets` |
| Swift / Vapor server-side app | `security-swift` + `security-api` + `security-secrets` |
| Mixed Swift + Objective-C app | `security-swift` + `security-objc` + `security-mobile` + `security-secrets` |
| Go web service or API | `security-go` + `security-api` + `security-secrets` |
| Go microservice / cloud-native | `security-go` + `security-iac` + `security-secrets` |
| Rust web service or API | `security-rust` + `security-api` + `security-secrets` |
| Rust CLI / embedded / systems | `security-rust` + `security-secrets` |
| React SPA (Vite, CRA) | `security-react` + `security-javascript` + `security-secrets` |
| React + separate backend | `security-react` + `security-javascript` + relevant backend skill |
| Next.js full-stack app | `security-nextjs` + `security-react` + `security-secrets` |
| Next.js + external API | `security-nextjs` + `security-react` + `security-api` + `security-secrets` |
| Angular SPA | `security-angular` + `security-javascript` + `security-secrets` |
| Angular + separate backend | `security-angular` + `security-javascript` + relevant backend skill |
| Angular Universal (SSR) | `security-angular` + `security-javascript` + `security-secrets` |
| Vue.js SPA (Vite) | `security-vue` + `security-javascript` + `security-secrets` |
| Vue.js + separate backend | `security-vue` + `security-javascript` + relevant backend skill |
| Nuxt.js full-stack app | `security-vue` + `security-javascript` + `security-secrets` |
| Nuxt.js + external API | `security-vue` + `security-javascript` + `security-api` + `security-secrets` |
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
│   └── code-security-*.md             ← 16 detailed skill files (jvm covers Java + Kotlin)
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

### Java & Kotlin (JVM) Security

Unified security rules for Java 11+ and Kotlin 1.9+ on the JVM, covering Spring Boot backends. Sections 1–16 cover JVM-level vulnerabilities applicable to both languages: native deserialization gadget chains via `ObjectInputStream` (JEP 290 filter), `XMLDecoder`, XStream security framework, Jackson polymorphic typing, JNDI injection and Log4Shell (CVE-2021-44228 CVSS 10.0), SpEL injection (Spring4Shell CVE-2022-22965, Spring Cloud CVE-2022-22963/22947), SQL injection in JDBC/JPA/Hibernate, XXE in `DocumentBuilderFactory`/`SAXParserFactory`/`XMLInputFactory`, command injection via `Runtime.exec()`, AES-GCM vs DES/ECB/MD5, path traversal, LDAP injection, SSRF, Spring Security misconfiguration, mass assignment, ReDoS, log injection, and Maven/Gradle supply chain. Section 17 covers Kotlin-specific risks: `kotlinx.serialization` `@Polymorphic` deserialization, `data class` sensitive field leakage via auto-generated `toString()`, `!!` operator as security anti-pattern, coroutine + Spring Security context loss, `object` singleton race conditions, and Kotlin Scripting API (`ScriptEngineManager`/`kotlin-scripting-jsr223`) as an `eval`-equivalent RCE vector plus `kotlin-reflect` dependency auditing. Includes 12 real CVEs (CVSS 7.5–10.0, 2019–2023), a 56-item checklist (Java + Kotlin), and tooling including SpotBugs + FindSecBugs, detekt, Semgrep, and OWASP Dependency-Check.

### C# / .NET Security

Comprehensive security rules for C# and .NET 6+ applications. Covers 17 vulnerability classes including `BinaryFormatter`/`SoapFormatter` deserialization gadget chains, Newtonsoft.Json `TypeNameHandling` RCE, `DataSet.ReadXml()` (CVE-2020-1147), SQL injection via `FromSqlRaw`, XXE in `XmlDocument`, command injection via `Process.Start`, cryptographic misuse (AES-GCM vs ECB/MD5/DES), path traversal with `Path.Combine`, LDAP injection, ReDoS in `System.Text.RegularExpressions`, TLS bypass in `HttpClient`, SSRF, ASP.NET Core CORS/CSRF/session security, unsafe code / `stackalloc` buffer overflows, open redirect, sensitive data in logs (CVE-2021-34532), and NuGet supply chain. Includes 12 real CVEs (CVSS 5.5–9.8, 2020–2024), a 40-item security checklist, and a tooling table with Roslyn analyzers, Semgrep, and BinSkim.

### Clojure Security

Security rules for Clojure 1.11+ on the JVM, covering the Ring/Compojure web stack and next.jdbc. The most critical Clojure-specific risk is code execution via `eval` and `clojure.core/read-string` — this file explains why `clojure.edn/read-string` must be used instead for all external data. Additional sections cover: nREPL/REPL exposure (bind to `127.0.0.1`, disabled in production), EDN and Transit deserialization (including nippy `thaw` with password and length check), SQL injection via `next.jdbc` parameterized vectors, Ring middleware security (`wrap-defaults`, `ring.middleware.anti-forgery`, session fixation prevention), OS command injection via `clojure.java.shell/sh`, path traversal via `clojure.java.io`, cryptography via Java interop (buddy-hashers, SecureRandom, AES-GCM), sensitive data in timbre logs (redaction middleware), and Leiningen/deps.edn supply chain (lein-nvd, clj-watson). Includes a Java Interop Security Note pointing to `security-jvm` for ObjectInputStream, JNDI, XXE, and Log4j risks. Contains 5 real CVEs, a 35-item security checklist, and tooling including clj-holmes, eastwood, and Semgrep Clojure rules.

### Elixir Security

Security rules for Elixir 1.15+ and Phoenix 1.7+, covering 16 security domains specific to the BEAM VM and its ecosystem. The most critical Elixir-specific risks that do not exist in most other languages are: **atom exhaustion** (`String.to_atom/1` with user input grows the atom table indefinitely until VM crash — use `String.to_existing_atom/1`) and **ETF deserialization** (`:erlang.binary_to_term/1` without `[:safe]` flag enables atom creation and potential RCE gadgets — always use the safe flag or prefer JSON). Phoenix-specific sections cover: `Code.eval_string`/`EEx.eval_string` code injection, `:os.cmd/1` vs `System.cmd/3` command injection, Ecto SQL injection via `fragment/1` string interpolation, path traversal with `Path.expand/1`, SweetXml/xmerl XXE (use `Saxy` instead), cryptography with `:crypto` AES-256-GCM and `Bcrypt`/`Argon2`, Guardian JWT misconfiguration, Phoenix LiveView authorization in `handle_event/3`, session fixation prevention (`configure_session(conn, renew: true)`), compile-time vs runtime secrets (`config/runtime.exs` with `System.fetch_env!/1`), CORS and CSRF in Plug pipelines, and process/message security. Critically includes CVE-2025-32433 — the March 2025 Critical (10.0) unauthenticated RCE in Erlang/OTP SSH daemon that affects all Elixir applications on unpatched OTP. Contains 8 real CVEs (2019–2025), a 50-item security checklist, and tooling including Sobelow and mix_audit.

### C / C++ Security

Security rules for C11/C17 and C++17/C++20, covering 16 security domains specific to systems programming. The most critical C/C++-specific risks are: **buffer overflow via dangerous C stdlib functions** (`gets`, `strcpy`, `strcat`, `sprintf` — all forbidden; use `fgets`, `strncpy`/`strlcpy`, `snprintf` with explicit size limits), **use-after-free and dangling pointers** (mitigated with RAII, `std::unique_ptr`/`shared_ptr`, and never returning pointers to local variables), **integer overflow** (signed overflow is undefined behavior in C/C++ — use `__builtin_mul_overflow`, `std::numeric_limits` checks, or C23 `stdckdint.h`), and **format string injection** (`printf(user_input)` enables stack read/write — always use `printf("%s", input)`). Unique sections include: **cryptographic memory zeroization** (`memset` can be optimized away by the compiler — use `explicit_bzero`, `memset_s`, or `SecureZeroMemory` on Windows), **CSPRNG** (`rand()` is not cryptographically secure — use `getrandom(2)`, `arc4random_buf`, or `/dev/urandom`), **TOCTOU race conditions** (`access()+open()` pattern — use `O_NOFOLLOW` flag and `openat()`), **compiler hardening flags** (`-fstack-protector-strong`, `-pie`, RELRO, `-D_FORTIFY_SOURCE=3`, CFI, AddressSanitizer/UBSanitizer/MemorySanitizer), **C++ exception safety and RAII** (`lock_guard`/`scoped_lock` for mutexes, `unique_ptr` custom deleters), and **supply chain** (CMake `FetchContent_Declare` SHA pinning, CVE-2024-3094 XZ Utils backdoor). Contains 10 real CVEs (Heartbleed, Baron Samedit, regreSSHion, XZ backdoor, and others), a 50-item security checklist, and 11 tools (ASan, UBSan, MSan, Valgrind, cppcheck, Clang Static Analyzer, CodeQL, Semgrep, Coverity, checksec, Flawfinder).

### Dart / Flutter Security

Security rules for Dart 3.x and Flutter 3.x, covering mobile (Android/iOS), Dart server-side, and Flutter web. The most common critical finding in Flutter penetration tests is **insecure local storage** — `SharedPreferences` and unencrypted Hive boxes store data as plaintext XML/binary on the device; all secrets must use `flutter_secure_storage` (Android Keystore / iOS Keychain). The second most common critical is **TLS bypass**: the `badCertificateCallback = (_, __, ___) => true` pattern disables all certificate validation, enabling trivial MitM attacks. Additional sections cover: **weak PRNG** (`dart:math Random()` has 32-bit entropy — the Zellic Research 2024 finding showed Proton Wallet's BIP39 mnemonic was brute-forceable in 16 minutes; always use `Random.secure()`), **SQL injection in `sqflite`** (CVE-2023-41387 CVSS 9.1 — `flutter_downloader` allowed session theft and arbitrary file write via unparameterized queries), **command injection via `Process.run(runInShell: true)`**, **path traversal in `dart:io` File operations** (CVE-2024-54461), **WebView JavaScript bridge abuse** (CVE-2020-6506 UXSS), **deep link/URL scheme hijacking** (custom `myapp://` schemes interceptable by any installed app — use HTTPS App Links/Universal Links), **biometric authentication bypass** (Frida-hookable boolean result — use hardware-backed `CryptoObject`), **hardcoded secrets via `--dart-define`** (values appear in Base64 in iOS `Info.plist` and are extractable from Android binaries via `blutter`), **sensitive data in `print()` logs** (not stripped in release mode — visible in `adb logcat`), **`dart:ffi` memory safety** (bypasses Dart GC — use `Arena` for scoped allocation), **cryptography misuse** (AES-ECB mode, IV reuse, `package:crypto` MD5/SHA-1 for passwords), **JWT validation** (`JWT.decode()` skips signature — always use `JWT.verify()`), and **pub.dev supply chain** (`dart pub audit` + osv-scanner in CI). Contains 11 real CVEs (2020–2026, CVSS 3.0–9.8), a comprehensive security checklist, and 12 tools including MobSF, objection, blutter, and freeRASP.

### Objective-C Security

Security rules for Objective-C and Objective-C++ targeting iOS 14+ and macOS 12+. Objective-C is uniquely dangerous because it combines **C runtime hazards** (buffer overflows, format string injection, use-after-free) with a **highly dynamic message-passing runtime** that enables runtime attacks not possible in memory-safe languages. The most critical Objective-C-specific risks are: **NSKeyedUnarchiver deserialization** (CVE-2019-8641 — `[NSKeyedUnarchiver unarchiveObjectWithData:]` allows arbitrary class instantiation via gadget chains; always restrict with `allowedClasses` and `requiresSecureCoding`), **KVC injection** (`setValue:forKeyPath:` and `valueForKeyPath:@"@sum.field"` with user-controlled keys enables operator injection and property access on unexpected objects — use an allowlist), **NSPredicate format string injection** (`predicateWithFormat:userString` is Core Data's SQL injection equivalent — always use `%@` / `%K` placeholders), and **`performSelector:` / `NSClassFromString` / `NSSelectorFromString` with user input** (enables arbitrary method invocation — restrict to an explicit allowlist). Storage sections cover: **`NSUserDefaults` for secrets** (plaintext plist, never for tokens/passwords — use Keychain with `kSecAttrAccessibleWhenUnlockedThisDeviceOnly`), **`NSFileManager` without `NSFileProtectionComplete`**, and **Keychain `kSecAttrAccessibleAlways`** (accessible even when device is locked — a critical misconfiguration). Network sections cover: **`didReceiveAuthenticationChallenge` unconditionally accepting certificates** (trivial MitM), **`NSAllowsArbitraryLoads: YES` in Info.plist** (disables ATS for all domains), and **certificate pinning via `SecTrustEvaluateWithError`**. Additional sections cover: C-inherited buffer overflows (`strcpy`/`sprintf` — use `strlcpy`/`snprintf`), `NSLog` logging sensitive data (visible in device Console in production — not stripped), `LAContext evaluatePolicy:` biometric bypass (Frida-hookable boolean — use hardware-backed Keychain items with `kSecAccessControlBiometryCurrentSet`), Core Foundation ARC bridging mistakes (`__bridge` vs `__bridge_transfer` — wrong choice causes double-free or memory leaks), `NSXMLParser`/libxml2 XXE, binary hardening (`PIE`, stack canaries, `get-task-allow: false`), and CocoaPods supply chain (CVE-2023-38894 — trunk server account takeover affecting 3 million apps). Contains 8 real CVEs (including Operation Triangulation chain: CVE-2023-32434 + CVE-2023-32435), 55-item checklist, and 12 tools including class-dump, Hopper, Frida, objection, and MobSF.

### Swift Security

Security rules for Swift 5.x/6.x on iOS 16+/macOS 13+ and server-side Swift (Vapor 4). Swift eliminates C-level memory hazards present in Objective-C, but introduces its own distinct security pitfalls. The most critical Swift-specific risks are: **force-unwrap (`!`) as a DoS vector** — `let value = dict["key"]!` crashes with a nil attacker-controlled JSON response; always use `guard let` or `if let` for external data; **`UnsafePointer` / `UnsafeMutableRawPointer` bypassing Swift's memory safety** — buffer overflows are possible when copying C data without explicit bounds validation; **`Codable` mass assignment** — decoding untrusted JSON directly into a domain model exposes privileged fields (`isAdmin`, `balance`, `role`) to attacker control; always use a separate input DTO with only the fields the caller should set; **`@objc dynamic` re-introducing ObjC runtime risks** — security-critical methods marked `dynamic` are swizzlable via Frida/`method_exchangeImplementations`; mark them `final` and never `@objc dynamic`; and **CryptoKit misuse** — `SHA256.hash(data: password)` is not password hashing (no salt, fast to brute-force — use PBKDF2 or send to server using bcrypt/Argon2); AES-GCM nonce reuse with the same key breaks both confidentiality and authenticity. Vapor-specific sections cover: **SQL injection via `db.raw("\(userValue)")`** — use `\(bind: value)` interpolation or Fluent ORM; **Leaf `#unsafeHTML()` XSS**; **Vapor JWT with empty `verify()` method** (no `exp`/`iss`/`aud` validation); **CRLF injection in `HTTPHeaders`**; and **Swift Package Manager supply chain** (`Package.resolved` must be committed; use `.exact()` version pinning; always provide `checksum` for binary targets — CVE-2024-38366 was a Critical 10.0 RCE in CocoaPods trunk via shell injection). Additional sections cover: **Swift strict concurrency** (enable `-strict-concurrency=complete` for Swift 6; use `actor` for shared mutable state — not `class` with manual locking), **ReDoS in `NSRegularExpression`/`Regex`**, **open redirect in `onOpenURL`/`openURL`**, **`WKWebView evaluateJavaScript` XSS** (use `callAsyncJavaScript(arguments:)` instead), **`os_log privacy: .public`** (explicitly opts out of redaction — default `.private` is correct for sensitive values), **`@AppStorage`/`UserDefaults` for tokens** (plaintext plist), and **hardcoded secrets extractable via `strings`/Hopper**. Contains 9 real CVEs (2022–2024, CVSS 5.3–10.0), a 62-item checklist, and 14 tools including SwiftLint, dsdump, Frida, objection, osv-scanner, and Instruments Memory Debugger.

### Go Security

Security rules for Go 1.21+ covering web services, microservices, CLIs, and cloud-native workloads (net/http, gin, echo, gRPC, GORM). Go eliminates C-level memory hazards but has its own distinct risk profile. The most critical Go-specific risks are: **goroutine data races on maps** — concurrent read+write on a `map` without `sync.RWMutex` is undefined behavior causing random crashes and security bypasses (run `go test -race ./...` in CI); **`os/exec` with shell invocation** — `exec.Command("sh", "-c", userInput)` enables command injection via shell metacharacters; always pass arguments as separate elements to `exec.Command`; **SQL injection via `fmt.Sprintf`** — `db.Query(fmt.Sprintf("...%s", id))` is Go's most common injection pattern because the ecosystem is less ORM-heavy than other languages; always use `$1`/`?` parameterized placeholders; **`text/template` vs `html/template`** — `text/template` has zero auto-escaping and is a trivial XSS vector for HTML output (CVE-2023-24540 and CVE-2023-29400 were both `html/template` escaping bugs in Go itself); and **missing HTTP server timeouts** — `http.ListenAndServe(":8080", mux)` has no `ReadTimeout`, `WriteTimeout`, or `IdleTimeout`, making every service trivially vulnerable to Slowloris and HTTP/2 Rapid Reset (CVE-2023-44487). Network sections cover: **SSRF via `http.Get(userURL)`** (block private IPs with `net.IP.IsPrivate()`; resolve hostnames to check for DNS rebinding); **`tls.Config{InsecureSkipVerify: true}`** (disables all certificate validation); and **JWT algorithm confusion** (CVE-2020-26160 in `dgrijalva/jwt-go` — migrate to `golang-jwt/jwt/v5` and always check `token.Method` type). Additional sections cover: **path traversal** (`filepath.EvalSymlinks` + prefix check), **JSON deserialization** (`DisallowUnknownFields()`, `MaxBytesReader`), **open redirect** (`url.Parse` + `IsAbs()` check), **CRLF header injection**, **goroutine leaks** (`defer cancel()` after every `WithTimeout`), **sensitive data in `slog`** (`LogValuer` interface for automatic redaction), **integer overflow in `make()`** (bounds-check before allocation), **panic recovery middleware**, and **supply chain** (`go.sum` committed, `go mod verify`, `govulncheck ./...` in CI). Contains 9 real CVEs (2020–2024, CVSS 5.5–7.5+), a 72-item checklist, and 13 tools including `gosec`, `govulncheck`, `golangci-lint`, `go test -race`, `goleak`, and `staticcheck`.

### Ruby Security

Security rules for Ruby 3.x and Ruby on Rails 7.x, covering 16 security domains specific to the language and its most popular frameworks. The most dangerous Ruby-specific risks are `Marshal.load` RCE (never deserialize untrusted Marshal data), `YAML.load` gadget chains (use `YAML.safe_load`), and the `^`/`$` vs `\A`/`\z` anchor confusion in regex validation — a silent validator bypass that is virtually impossible to detect without knowing the pitfall. Rails-specific sections cover: `eval`/`instance_eval`/`ERB.new` code injection, `send`/`public_send` dynamic dispatch allowlisting, ActiveRecord SQL injection via string interpolation in `where`/`order`/`group`, shell command injection (array form vs string form), path traversal with `render file:` (CVE-2019-5418), mass assignment via `params.permit!`, XSS through `html_safe`/`raw`, open redirect via `redirect_to params[:return_to]` (CVE-2021-44528, CVE-2024-41128), SSTI via `render params[:template]`, Nokogiri XXE, session fixation (`reset_session` before login), IDOR prevention with Pundit/CanCanCan, file upload validation by magic bytes via CarrierWave/ActiveStorage, and log filtering for sensitive parameters. Contains 10 real CVEs (2013–2024), a 45-item security checklist, and tooling including Brakeman, bundler-audit, RuboCop, and Semgrep Ruby rules.

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
