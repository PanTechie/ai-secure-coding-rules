# CLAUDE.md — Project Intelligence for ai-secure-coding-rules

This file captures project conventions, processes, and goals so any Claude Code session can continue work without rebuilding context from scratch.

---

## Project Goal

A curated collection of security rules and skills for AI coding assistants. The goal is **drop-in security awareness** — copy the relevant folder to any project and the AI assistant starts writing secure code by default, without requiring manual prompting.

**Supported platforms:** Claude Code, Gemini Antigravity, OpenAI Codex, Cursor.

**Planned skill categories (in order of priority):**
1. **Security standards** — OWASP, CWE, NIST, CISA (done: web, API, LLM, ASVS, mobile, secrets, IaC, CWE, privacy, SbD)
2. **Programming languages** — Python 3 ✅, PHP ✅, JavaScript & TypeScript ✅ (combined: `security-javascript`), C# ✅ (`security-csharp`), Java & Kotlin ✅ (combined JVM skill: `security-jvm`), Clojure ✅ (`security-clojure`), Ruby ✅ (`security-ruby`), Elixir ✅ (`security-elixir`), C/C++ ✅ (`security-c-cpp`), Objective-C ✅ (`security-objc`), Swift ✅ (`security-swift`), Go ✅ (`security-go`), Rust ✅ (`security-rust`)
3. **Frameworks** — React ✅ (`security-react`), Next.js ✅ (`security-nextjs`), Angular ✅ (`security-angular`), Vue.js/Nuxt ✅ (`security-vue`), Express.js ✅ (`security-express`), NestJS ✅ (`security-nestjs`), ASP.NET Core ✅ (`security-aspnetcore`), Django, FastAPI, Spring Boot, Laravel, Rails, etc.

> **Keep this list updated** — mark languages as ✅ when their skill is created. For everything else (conventions, formats, process), CLAUDE.md is stable and only needs editing when a new platform format is discovered or a convention changes. The `README.md` is the live registry of completed skills with line counts.

---

## Two-Tier Architecture

| Tier | File | How it loads | Purpose |
|------|------|-------------|---------|
| **Always-on** | `security-essentials.md` | Every interaction | ~92 critical rules + Security Review Workflow |
| **On-demand** | `code-security-*.md` | When AI deems relevant | Full rules, CVEs, code examples, checklists |

The essentials file is intentionally small. The detailed skill files are loaded only when the topic is relevant.

**Security Review Workflow** — `security-essentials.md` contains a four-phase workflow for all security reviews: (0) Context Discovery (project type, stack/versions, trust boundaries, existing controls), (1) Analysis Methodology — Taint Analysis (source→sink tracing), Reachability (is vulnerable path exposed?), Dependency Classification (direct vs transitive), Attack Path Analysis (worst-case chain), (2) Findings table with `Reachable` and `Dep Type` columns alongside severity/FP/recommendation, sorted Critical→Info, (3) ask which to fix, (4) post-fix status table. Lives in essentials so it applies to every skill. When updating essentials, always sync to all 4 platforms: `.claude/rules/`, `.agent/rules/`, `.cursor/rules/`, `AGENTS.md`.

---

## Repository Structure

```
standards/                          ← canonical source of truth (edit here first)
├── security-essentials.md
└── code-security-{domain}.md

.claude/                            ← Claude Code platform
├── rules/
│   └── security-essentials.md     ← copy of standards/security-essentials.md
└── skills/
    └── security-{domain}/
        ├── SKILL.md                ← trigger metadata + instruction
        └── rules.md                ← copy of standards/code-security-{domain}.md

.agent/                             ← Gemini Antigravity platform
├── rules/
│   └── security-essentials.md
└── skills/
    └── security-{domain}/
        ├── SKILL.md
        └── rules.md

.cursor/                            ← Cursor platform
└── rules/
    └── security-essentials.mdc    ← .mdc extension required; alwaysApply: true

AGENTS.md                           ← OpenAI Codex (always-on, full essentials inline)

vscode-extension/                   ← VSCode extension (TypeScript)
├── package.json                    ← extension manifest, commands, Marketplace metadata
├── tsconfig.json
├── .vscodeignore
├── CHANGELOG.md
└── src/
    ├── extension.ts                ← activate(); registers aiSecureRules.install + aiSecureRules.manage
    ├── skills.ts                   ← Platform type, PLATFORM_ITEMS, Skill interface, ALL_SKILLS (16)
    ├── installer.ts                ← install() + removeSkills(); tracks SHAs; returns Manifest
    └── manifest.ts                 ← Manifest type, blobSha(), readManifest/writeManifest,
                                       fetchRemoteShas() (GitHub Tree API), getSkillStatuses()
```

**VSCode extension commands:**
- `aiSecureRules.install` — QuickPick: platforms → skills → downloads + writes `.ai-secure-rules.json`
- `aiSecureRules.manage` — Fetches remote SHAs (1 GitHub API call), shows status per skill (up-to-date / outdated / installed-unknown / not-installed), lets user install/update/remove + writes updated manifest

**Manifest file:** `.ai-secure-rules.json` at workspace root — tracks `platforms[]` and `skillShas` (skillKey → git blob SHA of `rules.md`). Written by both commands. Fallback: if file absent but skill directories exist, reports `installed-unknown` (handles shell-script installs).

**Key rule:** `standards/` is the single source of truth. All `rules.md` files in platform skill directories are copies. After editing a `standards/` file, always sync:
```bash
cp standards/code-security-{domain}.md .claude/skills/security-{domain}/rules.md
cp standards/code-security-{domain}.md .agent/skills/security-{domain}/rules.md
```

---

## Naming Conventions

| Item | Convention | Example |
|------|------------|---------|
| Standards file | `code-security-{domain}.md` | `code-security-php.md` |
| Skill directory | `security-{domain}` | `security-php` |
| Language skills | `code-security-{language}.md` | `code-security-java.md` |
| Framework skills | `code-security-{framework}.md` | `code-security-django.md` |
| Standard skills | `code-security-{standard-name}.md` | `code-security-owasp-top10-2025.md` |

---

## Creating a New Skill — Step-by-Step

### 1. Research the domain thoroughly

Search for:
- Known CVEs (NVD, CVE Details, Snyk advisories)
- Language/framework-specific pitfalls (not just generic OWASP)
- Official documentation on dangerous functions/patterns
- OWASP cheat sheets, security advisories, Bandit/Semgrep rules
- Recent exploit techniques (2023–2025 range)

For language skills, always research:
- Deserialization vulnerabilities specific to that language
- Code execution sinks (eval equivalents, dynamic imports)
- Type coercion / comparison pitfalls
- File/path operation risks
- Cryptography misuse patterns
- Supply chain tooling (package manager audit command)
- Language-specific pitfalls that don't appear in generic guides

### 2. Create `standards/code-security-{domain}.md`

Follow this exact structure:

```markdown
# {Emoji} {Language/Domain} Security Rules

> **Standard:** {Description of scope}
> **Sources:** {Comma-separated list of authoritative sources}
> **Version:** 1.0.0
> **Last updated:** {Month Year}
> **Scope:** {What is and isn't covered}

---

## General Instructions

{One paragraph describing how to apply these rules}

---

## 1. {Category Name}

**Vulnerability:** {What the risk is and why it exists}

**References:** {CWE-XXX, CVE-XXXX-XXXXX, OWASP reference}

### Mandatory Rules

- **Rule written in imperative form** — always starts with an action verb.
- Rules use bold for the critical action, followed by reasoning after em dash.

```{language}
// ❌ INSECURE — short explanation
bad_code_example()

// ✅ SECURE — short explanation
good_code_example()
```

---

## CVE Reference Table

| CVE | Severity | Component | Description | Fixed In |
|-----|----------|-----------|-------------|----------|
| CVE-XXXX-XXXXX | Critical (9.x) | ... | ... | version X.Y.Z |

---

## Security Checklist

### {Category}
- [ ] Checklist item
- [ ] Checklist item

---

## Tooling

| Tool | Purpose | Command |
|------|---------|---------|
| [Tool](url) | What it checks | `command` |
```

**Quality bar for language/framework skills:**
- Minimum 10 sections covering the domain's major vulnerability classes
- Each section has at least one ❌ insecure + one ✅ secure code example
- CVE Reference Table with at least 5 real CVEs
- Security Checklist organized by category
- Tooling table with static analysis, dependency scanning, and runtime tools
- Always include language-specific pitfalls (not just generic OWASP repeats)
- Always research and include pitfalls that are easy to miss in code review

### 3. Create `.claude/skills/security-{domain}/SKILL.md`

```yaml
---
name: {Descriptive Name} Security
description: >
  Activate when writing or reviewing {language/domain} code involving {comma-separated
  list of trigger topics — be specific: function names, vulnerability types, patterns}.
  Also activate when the user mentions CVE, {key terms}, or asks for a {domain} security review.
allowed-tools: Read
---

Read the `rules.md` file in this skill directory and apply those security rules to all code analysis and generation tasks.
```

**Rules for SKILL.md description:**
- Be specific about trigger topics — list actual function/class names, not just vague categories
- Include both technical triggers (function names) and intent triggers (CVE, security review)
- Keep under 6 lines in the description block

### 4. Create `.claude/skills/security-{domain}/rules.md`

```bash
cp standards/code-security-{domain}.md .claude/skills/security-{domain}/rules.md
```

### 5. Create `.agent/skills/security-{domain}/SKILL.md`

Antigravity requires a body with two specific sections:

```yaml
---
name: {Descriptive Name} Security
description: >
  {Same description as Claude Code SKILL.md}
---

## Use this skill when

{Same trigger text as description, written as a paragraph}

## Instructions

Read the `rules.md` file in this skill directory and apply those security rules to all code analysis and generation tasks.
```

### 6. Create `.agent/skills/security-{domain}/rules.md`

```bash
cp standards/code-security-{domain}.md .agent/skills/security-{domain}/rules.md
```

### 7. Update `README.md`

Four places to update:

**a) Detailed Skills table** — add a row:
```markdown
| [`standards/code-security-{domain}.md`](...) | {Sources} | {Domain description} | {lines} | ~{rules} |
```
Then update the **Total (detailed)** row and the **Total including essentials** line.

**b) Claude Code structure listing** — add skill entry in the `.claude/skills/` block:
```
├── security-{domain}/
│   ├── SKILL.md                ← trigger: {key topics}
│   └── rules.md                ← {Domain} Security ({N} lines)
```

**c) Choose which skills table** — add project type rows:
```markdown
| {Project type} | `security-{domain}` + `security-secrets` |
```

**d) Update counts** — update the intro paragraph ("1,100+ security rules across 13 files").

---

## Platform-Specific Format Rules

### Claude Code (`.claude/`)

- Skills directory: `.claude/skills/`
- Always-on rules directory: `.claude/rules/`
- SKILL.md **must** include `allowed-tools: Read` in frontmatter
- SKILL.md body **must** explicitly say to read `rules.md` — Claude does NOT auto-read files in the skill directory
- File extension: `.md`

### Gemini Antigravity (`.agent/`)

- Skills directory: `.agent/skills/`
- Always-on rules directory: `.agent/rules/`
- SKILL.md **must** have `## Use this skill when` and `## Instructions` body sections
- Frontmatter does NOT include `allowed-tools`
- File extension: `.md`

### Cursor (`.cursor/`)

- Rules directory: `.cursor/rules/`
- File extension: **`.mdc`** (NOT `.md` — Cursor ignores `.md` files in rules/)
- Always-on rules require `alwaysApply: true` in frontmatter
- No skill/on-demand concept — all `.mdc` files are always-on unless configured otherwise
- When adding new skills for Cursor, copy the standards file, rename to `.mdc`, and add frontmatter

### OpenAI Codex (`AGENTS.md`)

- Single file at project root: `AGENTS.md`
- Plain markdown, no frontmatter
- Maximum 32KB
- Always-on only — no on-demand skill loading
- Only the essentials content fits; for deeper coverage, reference individual files in prompts

---

## Reviewing Existing Skills for Completeness

When asked to review or improve an existing skill, check for:

1. **Language-specific pitfalls** that don't appear in generic OWASP guides
2. **Dangerous built-in functions** unique to that language (e.g., PHP's `extract()`, Python's `yaml.load()`)
3. **Type system edge cases** (PHP type juggling, Python duck typing edge cases)
4. **Standard library misuse** (wrong defaults, deprecated-but-present dangerous functions)
5. **Common bypass techniques** for mitigations (e.g., PHP stream wrappers bypassing LFI guards)
6. **Supply chain tooling** specific to that language's package manager
7. **CVE table completeness** — verify recent CVEs (2023–2025) are represented

After adding sections, always:
- Update the checklist in the same file
- Update SKILL.md trigger descriptions for both `.claude/` and `.agent/`
- Sync `rules.md` in both platform skill directories
- Update README.md line count

---

## Code Example Conventions

```
// ❌ INSECURE — one-line explanation of why it's bad
bad_pattern()

// ✅ SECURE — one-line explanation of what makes it safe
good_pattern()
```

- Use `// ❌ INSECURE` and `// ✅ SECURE` prefixes consistently
- Keep examples minimal — just enough to illustrate the pattern
- Show the attack payload or exploit technique in a comment when it helps
- Prefer realistic code over toy examples

---

## README.md Update Checklist

When adding a new skill, update ALL of the following:

- [ ] Intro paragraph — update file count and rule count
- [ ] Detailed Skills table — new row with accurate line count (`wc -l` the file)
- [ ] Total row in Detailed Skills table
- [ ] "Total including essentials" line
- [ ] Claude Code structure listing (`.claude/skills/` block)
- [ ] "Same N-skill structure" line in Gemini Antigravity section
- [ ] "Choose which skills" table — add relevant project types
- [ ] Repository Structure block — update `code-security-*.md` count comment

---

## Common Pitfalls to Avoid

- **Never edit `rules.md` files directly** — always edit `standards/` then sync
- **Never use `wc -l` before writing** — count after the file is complete
- **Cursor needs `.mdc`** — `.md` files are silently ignored in `.cursor/rules/`
- **Claude Code needs explicit read instruction** — `allowed-tools: Read` alone is not enough; the body must say "Read the `rules.md` file"
- **Antigravity needs body sections** — frontmatter-only SKILL.md files are not triggered
- **`in_array()` in PHP** — always note the strict `true` third argument (loose comparison by default)
- **Language skills vs framework skills** — language skills cover only stdlib; framework-specific patterns belong in a separate framework skill
