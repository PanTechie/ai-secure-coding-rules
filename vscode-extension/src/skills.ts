import { QuickPickItem } from 'vscode';

export const REPO_RAW =
  'https://raw.githubusercontent.com/PanTechie/ai-secure-coding-rules/main';

// ── Platforms ──────────────────────────────────────────────────────────────

export type Platform = 'claude' | 'agent' | 'cursor' | 'codex';

export interface PlatformItem extends QuickPickItem {
  id: Platform;
}

export const PLATFORM_ITEMS: PlatformItem[] = [
  {
    id: 'claude',
    label: '$(robot) Claude Code',
    description: '.claude/',
    detail: 'skills/ with SKILL.md + rules.md, rules/security-essentials.md',
  },
  {
    id: 'agent',
    label: '$(sparkle) Gemini Antigravity',
    description: '.agent/',
    detail: 'skills/ with SKILL.md + rules.md, rules/security-essentials.md',
  },
  {
    id: 'cursor',
    label: '$(edit) Cursor',
    description: '.cursor/',
    detail: 'rules/*.mdc (alwaysApply: true) — always-on only',
  },
  {
    id: 'codex',
    label: '$(file) OpenAI Codex',
    description: 'AGENTS.md',
    detail: 'Single file with essentials (32 KB limit)',
  },
];

// ── Skills ─────────────────────────────────────────────────────────────────

export interface Skill {
  /** Directory name under .claude/skills/ and .agent/skills/ */
  key: string;
  /** Human-readable label shown in QuickPick */
  label: string;
  /** Filename under standards/ (used for Cursor .mdc download) */
  stdFile: string;
  /** Short description for QuickPick detail line */
  detail: string;
}

export const ALL_SKILLS: Skill[] = [
  {
    key: 'security-api',
    label: 'API Security',
    stdFile: 'code-security-owasp-api-top10-2023.md',
    detail: 'OWASP API Top 10:2023 — REST/GraphQL, rate limiting, BOLA',
  },
  {
    key: 'security-asvs',
    label: 'OWASP ASVS 5.0',
    stdFile: 'code-security-owasp-asvs-5.0.md',
    detail: 'Verification Standard L1/L2/L3 — ~350 requirements',
  },
  {
    key: 'security-cwe',
    label: 'CWE Top 25:2025',
    stdFile: 'code-security-cwe-top25-2025.md',
    detail: 'MITRE/CISA code-level bug patterns — buffer overflows, injection, etc.',
  },
  {
    key: 'security-iac',
    label: 'Infrastructure as Code',
    stdFile: 'code-security-iac.md',
    detail: 'Docker, Kubernetes, Terraform, CI/CD, Cloud (OWASP + CIS + NSA/CISA)',
  },
  {
    key: 'security-javascript',
    label: 'JavaScript / TypeScript / Node.js',
    stdFile: 'code-security-javascript.md',
    detail: 'eval, prototype pollution, DOM XSS, ReDoS, supply chain',
  },
  {
    key: 'security-llm',
    label: 'LLM & AI Application Security',
    stdFile: 'code-security-owasp-llm-top10-2025.md',
    detail: 'OWASP LLM Top 10:2025 — prompt injection, RAG, excessive agency',
  },
  {
    key: 'security-mobile',
    label: 'Mobile Security (Android / iOS)',
    stdFile: 'code-security-mobile.md',
    detail: 'OWASP Mobile Top 10:2024 + MASVS 2.1 — Kotlin & Swift',
  },
  {
    key: 'security-php',
    label: 'PHP Security',
    stdFile: 'code-security-php.md',
    detail: 'PHP 8.x — type juggling, unserialize, SQL injection, LFI/RFI',
  },
  {
    key: 'security-privacy',
    label: 'Privacy & Data Protection',
    stdFile: 'code-security-privacy.md',
    detail: 'GDPR, LGPD, CCPA, APPI, PIPEDA, POPIA — NIST Privacy Framework',
  },
  {
    key: 'security-python3',
    label: 'Python 3 Security',
    stdFile: 'code-security-python3.md',
    detail: 'pickle, subprocess, eval, yaml.load, path traversal, cryptography',
  },
  {
    key: 'security-sbd',
    label: 'Secure by Design',
    stdFile: 'code-security-secure-by-design.md',
    detail: 'CISA SbD Principles + Pledge + NIST SSDF SP 800-218',
  },
  {
    key: 'security-secrets',
    label: 'Secrets Management',
    stdFile: 'code-security-secrets.md',
    detail: 'Vault, rotation, Git leak prevention, CI/CD credentials',
  },
  {
    key: 'security-web',
    label: 'Web Application Security',
    stdFile: 'code-security-owasp-top10-2025.md',
    detail: 'OWASP Top 10:2025 — XSS, SQLi, broken access control, etc.',
  },
  {
    key: 'security-csharp',
    label: 'C# / .NET Security',
    stdFile: 'code-security-csharp.md',
    detail: 'BinaryFormatter, SqlCommand, ASP.NET Core, NuGet supply chain',
  },
  {
    key: 'security-jvm',
    label: 'Java & Kotlin (JVM) Security',
    stdFile: 'code-security-jvm.md',
    detail: 'ObjectInputStream, Log4Shell, Spring4Shell, SpEL, coroutines',
  },
  {
    key: 'security-clojure',
    label: 'Clojure Security',
    stdFile: 'code-security-clojure.md',
    detail: 'eval/read-string, nREPL, Ring/Compojure, next.jdbc, nippy',
  },
  {
    key: 'security-ruby',
    label: 'Ruby & Rails Security',
    stdFile: 'code-security-ruby.md',
    detail: 'Marshal.load, YAML.load, eval, params.permit!, html_safe, Brakeman, bundler-audit',
  },
  {
    key: 'security-elixir',
    label: 'Elixir & Phoenix Security',
    stdFile: 'code-security-elixir.md',
    detail: 'atom exhaustion, binary_to_term, Code.eval_string, Ecto SQLi, LiveView, Sobelow',
  },
  {
    key: 'security-c-cpp',
    label: 'C / C++ Security',
    stdFile: 'code-security-c-cpp.md',
    detail: 'gets/strcpy, use-after-free, format string, TOCTOU, AddressSanitizer, compiler hardening',
  },
  {
    key: 'security-dart',
    label: 'Dart & Flutter Security',
    stdFile: 'code-security-dart.md',
    detail: 'Random.secure(), SharedPreferences, badCertificateCallback, sqflite SQLi, dart:ffi, MobSF',
  },
  {
    key: 'security-objc',
    label: 'Objective-C Security',
    stdFile: 'code-security-objc.md',
    detail: 'NSKeyedUnarchiver, KVC injection, NSLog, performSelector:, arc4random, CocoaPods supply chain',
  },
  {
    key: 'security-swift',
    label: 'Swift Security',
    stdFile: 'code-security-swift.md',
    detail: 'force-unwrap DoS, Codable mass assignment, CryptoKit, Vapor SQLi, actor isolation, SPM supply chain',
  },
  {
    key: 'security-go',
    label: 'Go Security',
    stdFile: 'code-security-go.md',
    detail: 'os/exec injection, database/sql SQLi, goroutine races, missing timeouts, SSRF, govulncheck',
  },
  {
    key: 'security-rust',
    label: 'Rust Security',
    stdFile: 'code-security-rust.md',
    detail: 'unsafe/Send+Sync, integer overflow, diesel/sqlx SQLi, AES-GCM nonce reuse, cargo-audit, RustSec',
  },
  {
    key: 'security-react',
    label: 'React Security',
    stdFile: 'code-security-react.md',
    detail: 'dangerouslySetInnerHTML XSS, javascript: URLs, localStorage tokens, CSP, Server Components, DOMPurify',
  },
  {
    key: 'security-nextjs',
    label: 'Next.js Security',
    stdFile: 'code-security-nextjs.md',
    detail: 'CVE-2025-29927 middleware bypass, Server Actions auth, NEXT_PUBLIC_ leaks, next-auth, SSRF, ISR cache poisoning',
  },
  {
    key: 'security-angular',
    label: 'Angular Security',
    stdFile: 'code-security-angular.md',
    detail: 'bypassSecurityTrust* XSS, CVE-2024-21490, CSRF, ReDoS in pipes, NgRx state exposure, PKCE, CSP ngCspNonce',
  },
  {
    key: 'security-vue',
    label: 'Vue.js / Nuxt Security',
    stdFile: 'code-security-vue.md',
    detail: 'v-html XSS, Vue.compile() SSTI, VITE_ secret leaks, Pinia state exposure, Nuxt SSRF, CSP, CVE-2025-30208',
  },
  {
    key: 'security-express',
    label: 'Express.js Security',
    stdFile: 'code-security-express.md',
    detail: 'middleware order auth bypass, SQL/NoSQL injection, CORS, Helmet, rate limiting, session/JWT, CSRF, multer, mass assignment',
  },
  {
    key: 'security-nestjs',
    label: 'NestJS Security',
    stdFile: 'code-security-nestjs.md',
    detail: 'APP_GUARD bypass, ValidationPipe mass assignment, class-transformer CVE-2022-21190, JWT alg:none, TypeORM/Prisma SQLi, SSRF, GraphQL depth limits',
  },
  {
    key: 'security-aspnetcore',
    label: 'ASP.NET Core Security',
    stdFile: 'code-security-aspnetcore.md',
    detail: 'middleware order, Identity lockout, IAuthorizationService IDOR, Data Protection API, CSRF, EF Core SQLi, SignalR, Blazor XSS, Minimal API, CVE-2024-35264',
  },
];
