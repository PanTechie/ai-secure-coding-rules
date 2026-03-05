# 🟨 JavaScript & TypeScript Security Rules

> **Standard:** Browser (DOM API), Node.js runtime, and TypeScript type-system security
> **Sources:** OWASP JS Security Cheat Sheet, Node.js Security WG, NVD/CVE, Snyk Advisories, Google Project Zero, OWASP ASVS
> **Version:** 1.0.0
> **Last updated:** March 2026
> **Scope:** Covers JavaScript (ES2022+), TypeScript 5.x, and Node.js 18+ standard library. Excludes framework-specific rules (React, Express, Next.js — covered in separate framework skills).

---

## General Instructions

Apply these rules when writing or reviewing any JavaScript or TypeScript code. JavaScript's dynamic nature, prototype chain, and late binding make it uniquely susceptible to prototype pollution, code injection via eval, and type confusion. TypeScript's type erasure means compile-time safety does not carry over to runtime — always validate external data at runtime regardless of type annotations. Node.js-specific risks (command injection, path traversal, SSRF) apply equally to server-side TypeScript.

---

## 1. Prototype Pollution

**Vulnerability:** Attacker-controlled keys like `__proto__`, `constructor`, or `prototype` in object merge/set operations can poison `Object.prototype`, affecting all objects in the process. This leads to property injection, authentication bypass, and in some server-side contexts, remote code execution. Libraries like Lodash, dset, and web3-utils have all had exploitable prototype pollution CVEs.

**References:** CWE-1321, CVE-2025-13465, CVE-2024-21529, CVE-2024-21505, CVE-2025-64718

### Mandatory Rules

- **Reject keys `__proto__`, `constructor`, and `prototype`** in any recursive merge, deep set, or clone function — attackers use these to pollute the global prototype chain.
- **Use `Object.create(null)` for dictionaries** that store user-controlled keys — objects with no prototype cannot be polluted.
- **Prefer `Map` over plain objects** when keys are user-supplied — `Map` is immune to prototype pollution.
- **Freeze the prototype in security-critical applications** with `Object.freeze(Object.prototype)` to prevent pollution globally.
- **Validate with a schema library** (Zod, Joi, ajv) before merging user input into objects.

```javascript
// ❌ INSECURE — recursive merge without key validation
function merge(target, source) {
  for (const key in source) {
    target[key] = source[key]; // attacker sets key = "__proto__"
  }
}
merge({}, JSON.parse('{"__proto__":{"isAdmin":true}}'));
console.log({}.isAdmin); // true — all objects now have isAdmin!

// ✅ SECURE — skip dangerous prototype keys
function safeMerge(target, source) {
  for (const key of Object.keys(source)) {
    if (key === '__proto__' || key === 'constructor' || key === 'prototype') continue;
    target[key] = source[key];
  }
}
```

```javascript
// ✅ SECURE — use Map for user-controlled keys
const store = new Map();
store.set(userKey, userValue); // Map keys never touch Object.prototype

// ✅ SECURE — Object.create(null) produces prototype-free object
const dict = Object.create(null);
dict[userKey] = userValue; // safe: no __proto__ to pollute
```

---

## 2. Code Execution Sinks

**Vulnerability:** JavaScript has multiple sinks that execute arbitrary code from strings: `eval()`, `new Function()`, `setTimeout`/`setInterval` with string arguments, `vm.runInNewContext()` (Node.js), and template tag abuse. Passing user-controlled strings to these sinks is equivalent to `exec()` in other languages. The Node.js `vm` module is **not** a security sandbox.

**References:** CWE-95, OWASP A03:2021

### Mandatory Rules

- **Never pass user-controlled strings to `eval()`** — it executes arbitrary JavaScript with full current-scope access.
- **Never use `new Function(userInput)`** — equivalent to eval; constructs and executes a function from a string.
- **Never pass string arguments to `setTimeout` or `setInterval`** — use function references instead; string form is an implicit eval.
- **Never use `vm.runInNewContext()` or `vm.runInThisContext()` with user input** — the Node.js `vm` module is not an isolation boundary.
- **Use `JSON.parse()` instead of `eval()` for JSON data** — `eval()` executes embedded code while `JSON.parse()` does not.

```javascript
// ❌ INSECURE — eval with user input (full scope access)
const result = eval(req.body.formula);

// ❌ INSECURE — new Function with user input
const fn = new Function('x', `return ${req.body.expr}`);

// ❌ INSECURE — setTimeout with string (treated as eval)
setTimeout(req.body.callback, 1000);

// ❌ INSECURE — vm.runInNewContext is not a sandbox
const vm = require('vm');
vm.runInNewContext(req.body.code, {}); // attacker can break out

// ✅ SECURE — use a safe expression parser for math
import { evaluate } from 'mathjs';
const result = evaluate(req.body.formula, {}); // sandboxed math only

// ✅ SECURE — use function reference, not string
setTimeout(() => sendEmail(userId), 1000);
```

---

## 3. DOM-Based XSS (Browser)

**Vulnerability:** DOM-based XSS occurs when attacker-controlled data flows from a JavaScript source (URL fragment, `postMessage`, `localStorage`, query params) into a dangerous DOM sink without sanitization. Unlike reflected/stored XSS, DOM XSS never touches the server, so server-side filtering is ineffective. React's `dangerouslySetInnerHTML` is equally dangerous.

**References:** CWE-79, OWASP A03:2021

### Mandatory Rules

- **Never assign user-controlled data to `innerHTML`, `outerHTML`, or `document.write()`** — use `textContent` for text, or sanitize with DOMPurify before HTML insertion.
- **Never use `dangerouslySetInnerHTML` in React without sanitization** — always pass DOMPurify output.
- **Validate the origin in `postMessage` handlers** — check `event.origin` against an allowlist before processing any data.
- **Never pass user data to `location.href`, `location.assign()`, or `location.replace()`** without validating the scheme — leads to `javascript:` URL injection.
- **Configure a Content Security Policy (CSP)** with `script-src 'nonce-{random}'` or hash-based allowlists to limit XSS impact even if a sink is missed.

```javascript
// ❌ INSECURE — innerHTML with user content
document.getElementById('output').innerHTML = location.hash.slice(1);

// ❌ INSECURE — postMessage without origin check
window.addEventListener('message', (event) => {
  document.body.innerHTML = event.data; // any origin can inject HTML
});

// ✅ SECURE — use textContent for text (never executes HTML)
document.getElementById('output').textContent = userInput;

// ✅ SECURE — sanitize before innerHTML
import DOMPurify from 'dompurify';
element.innerHTML = DOMPurify.sanitize(userInput);

// ✅ SECURE — validate origin in postMessage handler
const ALLOWED_ORIGIN = 'https://trusted.example.com';
window.addEventListener('message', (event) => {
  if (event.origin !== ALLOWED_ORIGIN) return;
  processMessage(event.data);
});
```

```jsx
// ❌ INSECURE — dangerouslySetInnerHTML in React without sanitization
<div dangerouslySetInnerHTML={{ __html: userContent }} />

// ✅ SECURE — sanitize first, then render
import DOMPurify from 'dompurify';
<div dangerouslySetInnerHTML={{ __html: DOMPurify.sanitize(userContent) }} />
```

---

## 4. Node.js Command Injection

**Vulnerability:** Node.js `child_process` functions execute system commands. The `shell: true` option passes arguments through the system shell, enabling injection via metacharacters (`;`, `|`, `&`, `` ` ``). CVE-2024-27980 shows Node.js-specific injection on Windows: batch file names (`.bat`, `.cmd`) bypass `shell: false` and execute through `cmd.exe` anyway.

**References:** CWE-78, CVE-2024-27980, OWASP A03:2021

### Mandatory Rules

- **Never use `shell: true` in `spawn()` or `execFile()`** — this routes arguments through the shell and enables metacharacter injection.
- **Prefer `execFile()` over `exec()`** — `exec()` always uses the shell; `execFile()` does not by default.
- **Always pass command arguments as an array** — never concatenate user input into the command string.
- **Validate file extensions before passing to `execFile()`** — on Windows, `.bat` and `.cmd` files trigger `cmd.exe` even with `shell: false` (CVE-2024-27980).
- **Run Node.js services with minimum required privileges** — never as root; drop capabilities after binding ports.

```javascript
// ❌ INSECURE — exec() always passes through shell
const { exec } = require('child_process');
exec(`convert ${req.body.filename} output.pdf`); // injection: filename = '; rm -rf /'

// ❌ INSECURE — shell:true enables metacharacter injection
const { spawn } = require('child_process');
spawn('ls', [userInput], { shell: true }); // ; | & all work

// ✅ SECURE — execFile with argument array, no shell
const { execFile } = require('child_process');
execFile('convert', [filename, 'output.pdf'], { shell: false }, callback);

// ✅ SECURE — validate extension before execFile (CVE-2024-27980 Windows bypass)
const allowedExtensions = new Set(['.png', '.jpg', '.pdf']);
const ext = path.extname(filename).toLowerCase();
if (!allowedExtensions.has(ext)) throw new Error('Invalid file type');
execFile('convert', [filename, 'output.pdf'], { shell: false }, callback);
```

---

## 5. Path Traversal

**Vulnerability:** String operations on file paths allow `../` traversal sequences to escape the intended directory. `path.join()` alone does not prevent traversal — the normalized result must be verified to remain within the base directory. CVE-2025-27210 demonstrates Windows device name traversal (CON, PRN, AUX, NUL) causing denial of service.

**References:** CWE-22, CVE-2025-27210, CVE-2024-21896

### Mandatory Rules

- **Always resolve and verify the canonical path** — use `path.resolve()` and confirm the result starts with the base directory prefix followed by `path.sep`.
- **Never trust user input as a filename or path component** — strip directory separators with `path.basename()` or validate against an allowlist.
- **Reject Windows reserved device names** (CON, PRN, AUX, NUL, COM1–9, LPT1–9) when handling paths on Windows or from Windows clients.
- **Use `path.resolve()` not `path.normalize()`** — `normalize()` does not anchor to a base directory; `resolve()` does.

```javascript
// ❌ INSECURE — path.join alone doesn't prevent traversal
const filePath = path.join('/var/www/uploads', req.query.file);
fs.readFile(filePath); // req.query.file = '../../etc/passwd' succeeds

// ✅ SECURE — resolve and verify prefix
const BASE_DIR = path.resolve('/var/www/uploads');
const filePath = path.resolve(BASE_DIR, req.query.file);
if (!filePath.startsWith(BASE_DIR + path.sep)) {
  throw new Error('Path traversal detected');
}
fs.readFile(filePath, callback);

// ✅ SECURE — strip all directory components for simple filename lookups
const filename = path.basename(req.query.file); // strips any ../
const filePath = path.join(BASE_DIR, filename);
```

```javascript
// ❌ INSECURE — Windows device name causes hang/error (CVE-2025-27210)
const name = req.query.name; // attacker sends "CON"
fs.readFile(path.join(dir, name)); // hangs indefinitely on Windows

// ✅ SECURE — reject reserved Windows names
const WINDOWS_RESERVED = /^(con|prn|aux|nul|com[0-9]|lpt[0-9])(\.|$)/i;
if (WINDOWS_RESERVED.test(path.basename(filename))) {
  throw new Error('Reserved filename rejected');
}
```

---

## 6. Deserialization

**Vulnerability:** Libraries like `node-serialize` execute JavaScript functions embedded in serialized data using IIFE patterns. When serialized data containing `_$$ND_FUNC$$_function(){...}()` is deserialized, the function is passed to `eval()` and executed — achieving RCE with a crafted JSON payload (CVE-2017-5941).

**References:** CWE-502, CVE-2017-5941

### Mandatory Rules

- **Never use `node-serialize` or any library that deserializes JavaScript functions** — the IIFE execution pattern cannot be safely sandboxed.
- **Never deserialize data from untrusted sources** without schema validation against a strict schema.
- **Use `JSON.parse()` only** for structured data — it cannot execute functions.
- **Validate all parsed objects with a schema library** (Zod, Joi, ArkType) before using deserialized fields.

```javascript
// ❌ INSECURE — node-serialize executes IIFE in data (CVE-2017-5941)
const serialize = require('node-serialize');
const payload = '{"rce":"_$$ND_FUNC$$_function(){require(\'child_process\').exec(\'id\',console.log)}()"}';
serialize.unserialize(payload); // function executed immediately — RCE!

// ✅ SECURE — use plain JSON.parse with schema validation
import { z } from 'zod';
const UserSchema = z.object({
  id: z.string().uuid(),
  name: z.string().max(100),
});
const data = UserSchema.parse(JSON.parse(rawInput)); // throws if invalid
```

---

## 7. NoSQL Injection (MongoDB)

**Vulnerability:** MongoDB queries accept JSON objects, allowing attackers to inject query operators (`$gt`, `$regex`, `$where`) when user input is directly embedded in query filter objects. The `$where` operator executes arbitrary JavaScript server-side. The `$gt: ""` trick bypasses password checks by matching any non-empty string.

**References:** CWE-943, OWASP A03:2021

### Mandatory Rules

- **Never use the `$where` operator** with user-controlled data — it executes JavaScript on the MongoDB server.
- **Always validate query parameters with a schema library** before building MongoDB queries.
- **Reject objects where primitive fields are expected** — check `typeof input === 'string'` (or use Zod) before embedding in queries.
- **Use Mongoose schemas** rather than raw filter objects from request bodies — Mongoose enforces field types.
- **Disable `$where` at the MongoDB server level** (`--noscripting` flag) if not needed.

```javascript
// ❌ INSECURE — request body directly in query (operator injection)
app.post('/login', async (req, res) => {
  const user = await User.findOne({
    username: req.body.username,
    password: req.body.password,
    // attacker sends: { "password": { "$gt": "" } }
    // $gt: "" matches any non-empty string — auth bypass!
  });
});

// ❌ INSECURE — $where with user input (server-side JS execution)
User.find({ $where: `this.username === '${req.body.name}'` });

// ✅ SECURE — validate types before querying
app.post('/login', async (req, res) => {
  const { username, password } = req.body;
  if (typeof username !== 'string' || typeof password !== 'string') {
    return res.status(400).json({ error: 'Invalid input' });
  }
  const user = await User.findOne({ username, password });
});

// ✅ SECURE — Zod schema enforces string types
import { z } from 'zod';
const LoginSchema = z.object({
  username: z.string().max(64),
  password: z.string().max(128),
});
const { username, password } = LoginSchema.parse(req.body);
const user = await User.findOne({ username, password });
```

---

## 8. Cryptography

**Vulnerability:** `Math.random()` is a deterministic PRNG seeded from time — not cryptographically secure, and outputs are predictable. The deprecated `crypto.createCipher()` derives a key from the password without a random IV, making it deterministic. Reusing IVs in GCM mode reveals the keystream. String equality for token comparison leaks timing information.

**References:** CWE-338, CWE-916, CWE-327, OWASP A02:2021

### Mandatory Rules

- **Never use `Math.random()` for security-sensitive values** — use `crypto.randomBytes()` or `crypto.randomUUID()`.
- **Never use `crypto.createCipher()` or `crypto.createDecipher()`** (deprecated since Node.js 10) — use `createCipheriv()` with a random IV.
- **Generate a fresh random IV for every encryption operation** — reusing an IV with AES-GCM leaks the keystream and breaks authentication.
- **Never use MD5 or SHA-1 for password hashing** — use bcrypt, scrypt, or Argon2id.
- **Use `crypto.timingSafeEqual()` for token and HMAC comparisons** — string equality (`===`) is vulnerable to timing attacks.
- **Use `crypto.randomBytes(32)` for session tokens and CSRF tokens** — minimum 256 bits of entropy.

```javascript
// ❌ INSECURE — Math.random() for token generation (predictable)
const token = Math.random().toString(36).substring(2);

// ✅ SECURE — cryptographically random token
import { randomBytes, randomUUID } from 'crypto';
const token = randomBytes(32).toString('hex'); // 256-bit unpredictable token
const uuid = randomUUID(); // cryptographic UUID v4

// ❌ INSECURE — createCipher without IV (deprecated, deterministic)
const cipher = crypto.createCipher('aes-256-cbc', key);

// ✅ SECURE — createCipheriv with random IV stored alongside ciphertext
const iv = randomBytes(16);
const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
// Store iv + authTag + ciphertext; all required for decryption

// ❌ INSECURE — timing-vulnerable comparison
if (req.headers['x-csrf-token'] === storedToken) { /* ... */ }

// ✅ SECURE — constant-time comparison prevents timing attacks
import { timingSafeEqual } from 'crypto';
const a = Buffer.from(req.headers['x-csrf-token'] ?? '');
const b = Buffer.from(storedToken);
if (a.length !== b.length || !timingSafeEqual(a, b)) {
  throw new Error('Invalid token');
}
```

---

## 9. ReDoS — Regular Expression Denial of Service

**Vulnerability:** Catastrophic backtracking occurs when a regex with nested quantifiers or alternation meets a crafted string, causing exponential evaluation time. On Node.js (single-threaded event loop), a single ReDoS input can freeze the entire server for seconds or indefinitely, denying service to all users.

**References:** CWE-1333, OWASP A06:2021

### Mandatory Rules

- **Audit regexes with nested quantifiers** (`(a+)+`, `(.+)*`, `(a|aa)+`) using `safe-regex` or `vuln-regex-detector` before deploying.
- **Use the `re2` npm package** for regexes applied to untrusted user input — RE2 (Google's engine) guarantees linear-time evaluation.
- **Never compile user-supplied regex patterns** with `new RegExp(userInput)` — reject or strictly validate patterns first.
- **Limit input length** before applying complex regexes — most ReDoS attacks require long strings to amplify backtracking.
- **Use simple, anchored patterns** where possible — a precise character class like `[a-zA-Z0-9._%+-]+` backtracks far less than `.*` or `.+`.

```javascript
// ❌ INSECURE — catastrophic backtracking (exponential with long input)
const emailRegex = /^([a-zA-Z0-9]*)([a-zA-Z0-9._-]*)+@.*$/;
emailRegex.test('a'.repeat(50) + '!'); // hangs for seconds

// ❌ INSECURE — user-controlled regex pattern
const re = new RegExp(req.query.pattern); // attacker supplies catastrophic pattern
re.test(userInput);

// ✅ SECURE — use RE2 engine for user-driven matching
import RE2 from 're2';
const re = new RE2(sanitizedPattern); // linear time, no backtracking
re.test(userInput);

// ✅ SECURE — limit input length before regex, use anchored pattern
if (email.length > 254) throw new Error('Email too long');
if (!/^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$/.test(email)) {
  throw new Error('Invalid email format');
}
```

---

## 10. Supply Chain Security

**Vulnerability:** The npm ecosystem is a major attack surface. In June 2024, a Chinese company acquired the Polyfill.io domain and weaponized the CDN script, injecting malware into 100,000+ websites including Hulu and Mercedes-Benz. npm packages can execute arbitrary code via `preinstall`/`postinstall` scripts at install time.

**References:** CWE-1395, OWASP A06:2021, Polyfill.io supply chain attack (June 2024)

### Mandatory Rules

- **Run `npm audit` in CI** and fail the build on high/critical severity vulnerabilities.
- **Commit `package-lock.json`** and use `npm ci` (not `npm install`) in CI to enforce exact versions.
- **Never load scripts from third-party CDNs without Subresource Integrity (SRI)** — the Polyfill.io attack weaponized a CDN script that millions of sites included unconditionally.
- **Use `--ignore-scripts` flag** when installing packages in automated environments — prevents malicious `postinstall` hooks.
- **Pin transitive dependencies** with `overrides` (npm 8.3+) or `resolutions` (Yarn) when a transitive dep has a critical vulnerability.
- **Audit package names for typosquatting** before installing — `lodash` vs `loadash`, `cross-env` vs `crossenv`.

```html
<!-- ❌ INSECURE — CDN script without SRI (Polyfill.io attack vector) -->
<script src="https://cdn.polyfill.io/v3/polyfill.min.js"></script>

<!-- ✅ SECURE — SRI hash pins exact file content; browser rejects any modification -->
<script
  src="https://cdnjs.cloudflare.com/ajax/libs/lodash.js/4.17.21/lodash.min.js"
  integrity="sha512-WFN04846sdKMIP5LKNphMaWzU7YpMyCU245etK3g/2ARYbPK9Ub18eG+ljU96qKRCWh+quCY7yefSmlkQw1ANQ=="
  crossorigin="anonymous"></script>
```

```bash
# ❌ INSECURE — npm install allows version drift and runs scripts
npm install

# ✅ SECURE — ci install: exact lock file, no postinstall scripts
npm ci --ignore-scripts
npm audit --audit-level=high
```

```json
// ✅ SECURE — pin vulnerable transitive dependency in package.json
{
  "overrides": {
    "vulnerable-transitive-dep": ">=2.0.1"
  }
}
```

---

## 11. TypeScript-Specific Pitfalls

**Vulnerability:** TypeScript types are erased at runtime — type annotations provide no runtime protection. Using `as any`, `as unknown as T`, or `@ts-ignore` suppresses type errors without making the code safe. `strict: false` disables critical checks including `strictNullChecks` and `noImplicitAny`. External data (API responses, user input, environment variables) has no type at runtime.

**References:** TypeScript Security Best Practices, CWE-20

### Mandatory Rules

- **Enable `strict: true` in `tsconfig.json`** — enables `strictNullChecks`, `noImplicitAny`, `strictPropertyInitialization`, and other critical checks.
- **Never use `as any` on external/user-supplied data** — validate at runtime with Zod, io-ts, or ArkType instead; the type annotation does not protect you.
- **Treat `@ts-ignore` and `@ts-nocheck` as code-review red flags** — they suppress errors that may reflect incorrect assumptions about data shapes.
- **Always validate external data at runtime** — TypeScript types exist only at compile time; JSON from APIs, user input, and `process.env` have no runtime type guarantee.
- **Never use double-cast `as unknown as T`** to force type assignment — this completely bypasses the type system.
- **Use `satisfies` operator** instead of `as` when you want compile-time type checking without widening the type.

```typescript
// ❌ INSECURE — as any bypasses type checking on user-controlled data
function processUser(data: any) {
  const user = data as User; // no validation; attacker controls shape
  if (user.role === 'admin') grantAdminAccess(); // bypassed with crafted input
}

// ❌ INSECURE — @ts-ignore hides a type error that may indicate a security issue
// @ts-ignore
const userId: string = req.body.id; // body.id could be an object (prototype pollution)

// ❌ INSECURE — double-cast defeats the type system entirely
const config = unsafeData as unknown as Config;

// ✅ SECURE — runtime validation with Zod; types inferred from schema
import { z } from 'zod';
const UserSchema = z.object({
  id: z.string().uuid(),
  role: z.enum(['user', 'admin']),
});
function processUser(data: unknown) {
  const user = UserSchema.parse(data); // throws if invalid; type is inferred
  if (user.role === 'admin') grantAdminAccess();
}
```

```json
// ✅ SECURE — tsconfig.json with strict mode and additional safety options
{
  "compilerOptions": {
    "strict": true,
    "noUncheckedIndexedAccess": true,
    "exactOptionalPropertyTypes": true,
    "noImplicitReturns": true,
    "forceConsistentCasingInFileNames": true
  }
}
```

---

## 12. SSRF — Server-Side Request Forgery

**Vulnerability:** Server-side code that fetches URLs from user input can be redirected to internal services (AWS metadata at 169.254.169.254, localhost services, internal APIs). Node.js's `fetch`/`http.request` follow redirects by default, enabling multi-hop SSRF. DNS rebinding can circumvent hostname-only checks.

**References:** CWE-918, OWASP A10:2021

### Mandatory Rules

- **Never fetch URLs constructed from user input** without validating the resolved host against an allowlist.
- **Block private IP ranges and link-local addresses** (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, 127.0.0.1/8, 169.254.0.0/16, ::1) before making outbound requests.
- **Disable automatic redirect following** or validate each redirect target against the same allowlist.
- **Resolve hostnames to IPs and validate the IP** — DNS rebinding can map an allowed hostname to an internal IP after the hostname check passes.

```javascript
// ❌ INSECURE — fetch with user-supplied URL
app.get('/proxy', async (req, res) => {
  const response = await fetch(req.query.url); // SSRF: attacker fetches internal metadata
  res.send(await response.text());
});

// ✅ SECURE — validate host against allowlist, disable redirects
const ALLOWED_HOSTS = new Set(['api.example.com', 'cdn.example.com']);
app.get('/proxy', async (req, res) => {
  let url;
  try {
    url = new URL(req.query.url);
  } catch {
    return res.status(400).json({ error: 'Invalid URL' });
  }
  if (!ALLOWED_HOSTS.has(url.hostname)) {
    return res.status(403).json({ error: 'Host not allowed' });
  }
  const response = await fetch(url.toString(), { redirect: 'error' });
  res.send(await response.text());
});
```

---

## 13. JWT and Authentication Token Security

**Vulnerability:** JWT algorithm confusion allows attackers to forge tokens: changing `alg` to `none` bypasses signature verification entirely; RS256-to-HS256 confusion uses the server's public key as the HMAC secret — an attacker with the public key can forge arbitrary tokens. These attack classes (CVE-2015-9235) have appeared in multiple JWT library implementations.

**References:** CWE-347, CVE-2015-9235, OWASP A07:2021

### Mandatory Rules

- **Always specify `algorithms` explicitly when verifying JWTs** — never accept the algorithm from the token header.
- **Reject tokens with `alg: none`** by explicitly allowlisting only `HS256`, `RS256`, `ES256`, or whichever algorithm your system uses.
- **Use sufficiently long, random secrets for HS256** — minimum 256 bits (`crypto.randomBytes(32)`); never use passwords or predictable values.
- **Prefer asymmetric algorithms (RS256/ES256)** for multi-service architectures — private key signs, public key verifies; no shared secret needed.
- **Validate `iss`, `aud`, and `exp` claims** — prevents token reuse across services and after expiry.

```javascript
// ❌ INSECURE — no algorithm specified (alg:none bypass works)
jwt.verify(token, secret); // attacker creates token with alg:"none", no signature needed

// ❌ INSECURE — algorithm taken from the token header (algorithm confusion)
const header = JSON.parse(Buffer.from(token.split('.')[0], 'base64').toString());
jwt.verify(token, secret, { algorithms: [header.alg] });
// RS256 → HS256: attacker signs with public key, server verifies with same public key

// ✅ SECURE — explicit algorithm allowlist; validate standard claims
jwt.verify(token, secret, {
  algorithms: ['HS256'],       // explicit; rejects "none" and unexpected algorithms
  issuer: 'https://auth.example.com',
  audience: 'https://api.example.com',
});
```

---

## CVE Reference Table

| CVE | Severity | Component | Description | Fixed In |
|-----|----------|-----------|-------------|----------|
| CVE-2024-27980 | High (8.1) | Node.js `child_process` | Windows: batch file (`.bat`/`.cmd`) as command name bypasses `shell: false`, enabling command injection | Node.js 21.7.2, 20.12.2, 18.20.2 |
| CVE-2025-27210 | High (7.5) | Node.js path handling | Windows reserved device names (CON, PRN, AUX) in paths cause process hang — DoS | Node.js 23.7.0, 22.14.0, 20.19.0 |
| CVE-2025-27209 | High (7.5) | Node.js V8 engine | HashDoS via crafted HTTP headers exploiting V8 rapidhash algorithm collisions | Node.js 23.7.0, 22.14.0, 20.19.0 |
| CVE-2024-21896 | High (8.6) | Node.js `path` module | Path traversal via `Buffer` monkey-patching in `node:path` module | Node.js 21.6.2, 20.11.1, 18.19.1 |
| CVE-2025-13465 | High (7.5) | lodash ≤ 4.17.21 | Prototype pollution via `merge()` and `mergeWith()` functions | No official patch; migrate to alternatives |
| CVE-2024-21529 | High (7.3) | dset ≤ 3.1.3 | Prototype pollution via `dset()` deep property setter function | dset 3.1.4 |
| CVE-2024-21505 | High (7.3) | web3-utils ≤ 4.2.0 | Prototype pollution in `mergeDeep()` utility function | web3-utils 4.2.1 |
| CVE-2025-64718 | High (7.5) | js-yaml 4.x | Prototype pollution via YAML `load()` with crafted YAML document | js-yaml 4.2.0 |
| CVE-2017-5941 | Critical (9.8) | node-serialize 0.0.4 | IIFE pattern in serialized JSON triggers `eval()` — remote code execution | No patch; abandon library |
| CVE-2015-9235 | Critical (9.8) | jsonwebtoken < 4.2.2 | JWT `alg:none` bypass allows unsigned tokens to pass verification | jsonwebtoken 4.2.2+ |

---

## Security Checklist

### Prototype Pollution
- [ ] All recursive merge/clone functions reject `__proto__`, `constructor`, `prototype` keys
- [ ] User-controlled key maps use `Map` or `Object.create(null)` instead of plain objects
- [ ] Schema validation (Zod/Joi) applied before merging external data into objects

### Code Execution
- [ ] `eval()` is not used with any external data
- [ ] `new Function()` is not used with user-controlled arguments
- [ ] `setTimeout`/`setInterval` receive function references, not string arguments
- [ ] `vm.runInNewContext()` is not used as a security sandbox for untrusted code

### DOM XSS (Browser)
- [ ] `innerHTML`/`outerHTML` assignments only receive DOMPurify-sanitized content
- [ ] `postMessage` handlers validate `event.origin` against an explicit allowlist
- [ ] `location.href` assignments validate the scheme (reject `javascript:`, `data:`)
- [ ] CSP header configured with nonce or hash-based `script-src` policy

### Node.js Command Injection
- [ ] `exec()` is not used with user-controlled input
- [ ] `spawn()`/`execFile()` use `shell: false`
- [ ] Command arguments passed as array, never string concatenation
- [ ] File extensions validated before passing to `execFile()` on Windows (block `.bat`/`.cmd`)

### Path Traversal
- [ ] All file paths resolved with `path.resolve()` and prefix-checked against base dir
- [ ] Windows reserved names (CON, PRN, NUL, etc.) rejected in filename inputs
- [ ] User-supplied filenames stripped with `path.basename()` before use

### Deserialization
- [ ] `node-serialize` or similar eval-based deserializers not used anywhere in the codebase
- [ ] All external data validated with schema library before processing
- [ ] `JSON.parse()` used for structured data; no unsafe custom revivers

### NoSQL Injection
- [ ] MongoDB `$where` operator is not used with user input
- [ ] `typeof` checks applied to query parameters that should be primitives
- [ ] Zod/Joi schema validation applied to all MongoDB query inputs

### Cryptography
- [ ] `Math.random()` not used for tokens, session IDs, or cryptographic purposes
- [ ] Fresh random IVs generated for every encryption operation
- [ ] Passwords hashed with bcrypt/scrypt/Argon2id, not SHA/MD5
- [ ] Token comparisons use `crypto.timingSafeEqual()`
- [ ] `crypto.createCipher()` (deprecated) is not used

### ReDoS
- [ ] Complex regexes audited with `safe-regex` or `vuln-regex-detector`
- [ ] User-controlled regex patterns rejected or run through RE2
- [ ] Input length limited before applying regexes to untrusted input

### Supply Chain
- [ ] `npm audit` runs in CI with fail-on-high threshold
- [ ] `npm ci` used (not `npm install`) in CI pipelines
- [ ] `package-lock.json` committed and validated in version control
- [ ] CDN scripts use Subresource Integrity (SRI) hashes
- [ ] `--ignore-scripts` used during automated installs

### TypeScript
- [ ] `strict: true` enabled in `tsconfig.json`
- [ ] No `as any` used on external/user-supplied data
- [ ] `@ts-ignore`/`@ts-nocheck` absent from security-sensitive code paths
- [ ] External data (API responses, user input, env vars) validated with Zod/io-ts at runtime

### SSRF
- [ ] Outbound URLs constructed from user input validated against host allowlist
- [ ] Private IP ranges blocked in URL validation logic
- [ ] Redirect following disabled or each redirect target validated

### JWT / Auth
- [ ] `algorithms` explicitly specified in `jwt.verify()` — never from token header
- [ ] `alg: none` cannot be accepted by any token verification path
- [ ] `iss`, `aud`, and `exp` claims validated on every token

---

## Tooling

| Tool | Purpose | Command |
|------|---------|---------|
| [npm audit](https://docs.npmjs.com/cli/v10/commands/npm-audit) | Vulnerability scanning for npm dependencies | `npm audit --audit-level=high` |
| [Snyk](https://snyk.io) | Dependency + code vulnerability scanning | `npx snyk test` |
| [ESLint security plugin](https://github.com/eslint-community/eslint-plugin-security) | Static analysis for security anti-patterns (eval, non-literal regexp, etc.) | `npx eslint --plugin security .` |
| [Semgrep](https://semgrep.dev) | SAST rules for JS/TS (prototype pollution, eval, injection) | `semgrep --config=p/javascript` |
| [safe-regex](https://github.com/nicolo-ribaudo/safe-regex) | Detect catastrophically backtracking regular expressions | `npx safe-regex 'pattern'` |
| [re2](https://github.com/uhop/node-re2) | RE2 regex engine — linear time evaluation, no ReDoS | `npm install re2` |
| [DOMPurify](https://github.com/cure53/DOMPurify) | HTML sanitization for DOM XSS prevention | `npm install dompurify` |
| [Zod](https://zod.dev) | Runtime schema validation with TypeScript type inference | `npm install zod` |
| [Socket.dev](https://socket.dev) | Supply chain malware detection for npm packages | socket CLI / GitHub App |
| [retire.js](https://retirejs.github.io/retire.js/) | Detect known-vulnerable JavaScript libraries | `npx retire` |
| [tsc --noEmit](https://www.typescriptlang.org/tsconfig#noEmit) | TypeScript strict type checking without build output | `npx tsc --noEmit --strict` |
