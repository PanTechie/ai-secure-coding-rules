# 🦀 Rust Security Rules

> **Standard:** Security rules for Rust 1.70+ applications including web services, CLIs, embedded systems, and WebAssembly targets.
> **Sources:** Rust Security Advisory Database (RustSec), OWASP Top 10:2025, CWE/MITRE, NVD/CVE Database, GitHub Advisory Database, Rust Secure Code Working Group, ANSSI Rust Security Guidelines, Google Project Zero
> **Version:** 1.0.0
> **Last updated:** March 2026
> **Scope:** Rust 1.70+ standard library and common crates (std::process::Command, diesel/sqlx/sea-orm, serde/bincode, ring/RustCrypto/rand, rustls/native-tls, reqwest/hyper/axum/actix-web, regex, tokio, rayon, std::ffi). WebAssembly-specific patterns are covered where applicable.

---

## General Instructions

Apply these rules when writing or reviewing Rust code. Rust's ownership system, borrow checker, and type system eliminate entire classes of memory safety vulnerabilities present in C/C++ — but Rust has its own distinct risk profile: **`unsafe` blocks bypass the borrow checker and can introduce use-after-free, buffer overflows, and data races**; **integer arithmetic wraps silently in release builds**, enabling allocation overflows and logic bypasses; **`unwrap()`/`expect()` on `Option`/`Result` panics at runtime**, making panic-triggered denial of service a real attack vector; **`std::process::Command` with shell forms enables command injection**; and **serialization with `bincode`/`ciborium` on untrusted data can cause heap corruption or stack overflows**. Cargo and the RustSec advisory database (`cargo audit`) provide strong supply-chain tooling — use them in every CI pipeline.

---

## 1. `unsafe` Code and Raw Pointer Safety

**Vulnerability:** `unsafe` blocks opt out of Rust's memory safety guarantees. Incorrect use of raw pointers (`*const T`, `*mut T`), dangling pointers, invalid transmutation, incorrect `Send`/`Sync` implementations, and unsound lifetime annotations within `unsafe` blocks introduce use-after-free, buffer overflows, data races, and arbitrary code execution — identical to C/C++ vulnerabilities.

**References:** CWE-119, CWE-416, CWE-476, CWE-362

### Mandatory Rules

- **Minimize `unsafe` surface area** — encapsulate all `unsafe` code in a small, clearly-bounded module with a safe public API; never scatter `unsafe` blocks across business logic.
- **Justify every `unsafe` block with a `// SAFETY:` comment** explaining the invariants that make the code sound; treat an unjustified `unsafe` block as a bug.
- **Never create dangling references** — ensure that raw pointers used inside `unsafe` outlive the reference, have the correct alignment, and point to initialized memory.
- **Verify pointer alignment** before dereferencing raw pointers — misaligned reads are undefined behavior even when the address is valid.
- **Never use `std::mem::transmute` across incompatible types** — use `bytemuck` or `std::mem::transmute` only between types with identical size and guaranteed layout (`#[repr(C)]` or `#[repr(transparent)]`).
- **Implement `Send` and `Sync` manually only when certain the type satisfies the invariants** — incorrect implementations expose data races; prefer deriving via composition of `Send`/`Sync` types.
- **Audit `unsafe` in dependencies** — use `cargo-geiger` to surface the `unsafe` footprint of transitive dependencies before adding them.

```rust
// ❌ INSECURE — raw pointer cast without alignment or validity check
let ptr = data.as_ptr() as *const u64;
let val = unsafe { *ptr }; // UB if data is not 8-byte aligned

// ✅ SECURE — alignment verified; invariant documented
// SAFETY: `data` has been verified to be 8-byte aligned and contains at least 8 initialized bytes.
let val = unsafe { std::ptr::read_unaligned(data.as_ptr() as *const u64) };

// ✅ SECURE — bytemuck provides safe transmutation with compile-time layout checks
let val: u64 = bytemuck::from_bytes(&data[..8]).clone();
```

---

## 2. Integer Overflow and Arithmetic Safety

**Vulnerability:** In Rust release builds, integer arithmetic wraps on overflow by default (unlike debug builds, which panic). Overflow in allocation sizes leads to under-allocated buffers and heap corruption. Truncating casts (`u64 as u32`) silently discard high bits.

**References:** CWE-190, CWE-191, CWE-195, RUSTSEC-2021-0003 (smallvec)

### Mandatory Rules

- **Use `checked_add`/`checked_mul`/`checked_sub`** for arithmetic that feeds into allocation sizes, buffer indices, or security-sensitive calculations.
- **Avoid as-casts between integer types** in security-sensitive paths — use `TryFrom`/`TryInto` to return an error on truncation.
- **Enable `overflow-checks = true` in `[profile.release]`** for production binaries where performance permits.
- **Never multiply untrusted lengths by element sizes without overflow checking** before passing to allocation functions.

```rust
// ❌ INSECURE — release build wraps: count=0x4000_0001, elem=8 → allocates 8 bytes
let buf: Vec<u8> = Vec::with_capacity(count * elem_size);

// ✅ SECURE — checked multiplication; returns error on overflow
let capacity = count.checked_mul(elem_size).ok_or(Error::Overflow)?;
let buf: Vec<u8> = Vec::with_capacity(capacity);

// ✅ SECURE — TryFrom returns Err on truncation
let index = u32::try_from(offset).map_err(|_| Error::IndexOutOfRange)?;
```

---

## 3. Command Injection via `std::process::Command`

**Vulnerability:** Passing user-controlled input to `Command::new("sh").arg("-c").arg(userInput)` interprets shell metacharacters, executing attacker-controlled commands.

**References:** CWE-78

### Mandatory Rules

- **Never use shell forms** — use `Command::new("binary")` with separate `.arg()` calls so the OS passes arguments directly to `execve`.
- **Never let user input control the binary name** — allowlist the binary path at compile time.
- **Validate and allowlist all user-supplied arguments** before adding them with `.arg()`.
- **Use explicit timeouts** via `tokio::time::timeout` to prevent resource exhaustion.

```rust
// ❌ INSECURE — shell interprets metacharacters; filename = "foo; rm -rf /"
let output = Command::new("sh")
    .arg("-c")
    .arg(format!("grep {} /var/log/app.log", filename))
    .output()?;

// ✅ SECURE — argument array; OS passes directly to execve, no shell expansion
let output = Command::new("/usr/bin/grep")
    .arg("--")
    .arg(&filename)
    .arg("/var/log/app.log")
    .output()?;
```

---

## 4. SQL Injection via Diesel, SQLx, and SeaORM

**Vulnerability:** String interpolation in raw SQL queries enables SQL injection. Raw SQL escape hatches bypass Diesel's compile-time protection.

**References:** CWE-89

### Mandatory Rules

- **Prefer Diesel's type-safe query builder** (`diesel::QueryDsl`) over raw SQL.
- **Always bind user-controlled values via `.bind()`/`$1` placeholders** — never interpolate them into the query string.
- **Allowlist ORDER BY column names and directions** — they cannot be parameterized.
- **In SQLx, prefer the `query!` macro** (compile-time query checking) over `query()` with runtime strings.

```rust
// ❌ INSECURE — SQL injection via format!
let q = format!("SELECT * FROM users WHERE email = '{}'", email);
diesel::sql_query(q).execute(&mut conn)?;

// ✅ SECURE — Diesel type-safe query builder
let user = users.filter(email.eq(&user_email)).first::<User>(&mut conn)?;

// ✅ SECURE — SQLx with bind parameter
let rows = sqlx::query("SELECT id FROM users WHERE name = $1")
    .bind(&name)
    .fetch_all(&pool)
    .await?;
```

---

## 5. Path Traversal and File System Operations

**Vulnerability:** User-controlled paths without canonicalization allow `../../etc/passwd` traversal. `Path::join` silently discards the base for absolute paths. CVE-2022-21658 was a TOCTOU race in `remove_dir_all`.

**References:** CWE-22, CWE-377, CVE-2022-21658

### Mandatory Rules

- **Canonicalize both the base directory and the user-supplied path** with `std::fs::canonicalize()`, then verify the result starts with the canonicalized base.
- **Never use `Path::join(user_input)` as the sole guard** — it silently discards the base for absolute inputs.
- **Update to Rust ≥ 1.58.1** for the CVE-2022-21658 fix.
- **Use `tempfile::NamedTempFile`** instead of constructing temporary file paths manually.

```rust
// ❌ INSECURE — traversal: user_path = "../../etc/shadow"
let path = Path::new("/srv/uploads").join(&user_path);

// ✅ SECURE — canonicalize both, then verify prefix
let base = fs::canonicalize("/srv/uploads")?;
let target = fs::canonicalize(base.join(&user_path))?;
if !target.starts_with(&base) {
    return Err(Error::PathTraversal);
}
```

---

## 6. Deserialization Security (serde, bincode, ciborium, postcard)

**Vulnerability:** `bincode`/`postcard` on untrusted data can trigger stack overflows via deeply nested structures or heap exhaustion. `serde_json` on unbounded input can consume unbounded memory.

**References:** CWE-502, CWE-400

### Mandatory Rules

- **Never use `bincode` on untrusted external data** without strict size limits.
- **Limit JSON nesting depth and body size** when using `serde_json` with untrusted input.
- **Use `#[serde(deny_unknown_fields)]`** on structs that accept external data.
- **Avoid `serde_json::from_reader` on unbounded streams** — read into a size-limited buffer first.

```rust
// ❌ INSECURE — bincode on untrusted network bytes; unbounded allocation
let msg: MyMessage = bincode::deserialize(&network_bytes)?;

// ✅ SECURE — read with explicit size limit before deserializing
const MAX_BODY: usize = 1 * 1024 * 1024; // 1 MiB
let value: MyStruct = serde_json::from_slice(&body[..MAX_BODY.min(body.len())])?;

// ✅ SECURE — reject unknown fields from external callers
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CreateUserRequest { username: String, email: String }
```

---

## 7. Cryptography Misuse (ring, RustCrypto, rand)

**Vulnerability:** `rand::thread_rng()` is not suitable for long-lived keys; nonce reuse with AES-GCM is catastrophic; deprecated crates have timing vulnerabilities (RUSTSEC-2021-0072, CVE-2023-49092).

**References:** CWE-330, CWE-327, CWE-338, RUSTSEC-2021-0072, CVE-2023-49092

### Mandatory Rules

- **Use `rand::rngs::OsRng` or `ring::rand::SystemRandom`** for all cryptographic key and nonce generation.
- **Generate a unique random 96-bit nonce for every AES-256-GCM encryption operation.**
- **Use `ring` or `RustCrypto` (`aes-gcm`, `chacha20poly1305`)** — avoid `rust-crypto` (unmaintained) and `sodiumoxide` < 0.2.7.
- **Use `rsa` ≥ 0.9.7** — earlier versions had a timing side-channel (CVE-2023-49092).
- **Use `argon2` or `bcrypt` for password hashing** — never SHA-2 alone.
- **Use `subtle::ConstantTimeEq`** for comparing MACs and tokens.
- **Wrap key material in `zeroize::Zeroizing<_>`** to zero on drop.

```rust
// ❌ INSECURE — thread_rng not suitable for keys
let key: [u8; 32] = rand::thread_rng().gen();

// ✅ SECURE — OS entropy for key generation
use rand::rngs::OsRng;
use rand::RngCore;
let mut key = [0u8; 32];
OsRng.fill_bytes(&mut key);

// ✅ SECURE — constant-time MAC comparison
use subtle::ConstantTimeEq;
if mac_from_request.ct_eq(&expected_mac).into() { ... }
```

---

## 8. TLS Configuration (rustls, native-tls, reqwest)

**Vulnerability:** `danger_accept_invalid_certs(true)` disables all TLS validation. `native-tls` may allow TLS 1.0/1.1 on older systems. CVE-2024-32650 was an infinite loop in rustls < 0.23.5.

**References:** CWE-295, CWE-326, CVE-2024-32650

### Mandatory Rules

- **Never set `danger_accept_invalid_certs(true)` or `danger_accept_invalid_hostnames(true)`** in production.
- **Prefer `rustls` over `native-tls`** — it enforces TLS 1.2+ and is memory-safe.
- **Set connection and request timeouts on every HTTP client** to prevent Slowloris.
- **Update `rustls` to ≥ 0.23.5** (CVE-2024-32650 fix).

```rust
// ❌ INSECURE — disables TLS validation
let client = reqwest::Client::builder().danger_accept_invalid_certs(true).build()?;

// ✅ SECURE — rustls with timeout
let client = reqwest::Client::builder()
    .use_rustls_tls()
    .timeout(std::time::Duration::from_secs(30))
    .build()?;
```

---

## 9. SSRF and HTTP Client Security (reqwest, hyper)

**Vulnerability:** User-supplied URLs passed to `reqwest::get()` can reach internal services (cloud metadata `169.254.169.254`, Redis). Default redirect following can bypass URL validation.

**References:** CWE-918

### Mandatory Rules

- **Never pass user-supplied URLs directly to `reqwest::get()` or `Client::request()`** without strict URL validation.
- **Validate the scheme** — only permit `https://`.
- **Resolve the hostname and validate the IP** against a blocklist (private, loopback, link-local ranges).
- **Limit or disable redirects** for user-supplied URLs.

```rust
// ❌ INSECURE — SSRF: user_url = "http://169.254.169.254/latest/meta-data/"
let response = reqwest::get(&user_url).await?;

// ✅ SECURE — scheme check + IP validation + no redirects
let client = reqwest::Client::builder()
    .redirect(reqwest::redirect::Policy::none())
    .timeout(std::time::Duration::from_secs(10))
    .build()?;
```

---

## 10. Panic Safety — `unwrap`/`expect` DoS Prevention

**Vulnerability:** `.unwrap()` on `None`/`Err` panics and can crash or terminate tasks in production. Attackers can trigger panics through crafted input.

**References:** CWE-390, CWE-248

### Mandatory Rules

- **Never use `.unwrap()` in request-handling code paths** — propagate errors with `?`.
- **Use `.get()` instead of direct index access** on untrusted indices.
- **Handle `JoinError` from Tokio tasks** — an unhandled panic in a task kills only that task.
- **Parse integers with `str::parse::<T>()` and `?`** rather than `.unwrap()`.

```rust
// ❌ INSECURE — panics if param is missing or invalid
let id: i32 = params.get("id").unwrap().parse().unwrap();

// ✅ SECURE — propagate errors; no panic path
let id: i32 = params
    .get("id")
    .ok_or(Error::MissingParam("id"))?
    .parse()
    .map_err(|_| Error::InvalidParam("id"))?;
```

---

## 11. Concurrency Safety — Poisoned Mutexes and Deadlocks

**Vulnerability:** Incorrect `Send`/`Sync` implementations introduce data races (CVE-2022-23639). `Mutex::lock().unwrap()` silently propagates poisoning. Inconsistent lock ordering causes deadlocks.

**References:** CWE-362, CWE-833, CVE-2022-23639

### Mandatory Rules

- **Handle mutex poisoning explicitly** with `.unwrap_or_else(|e| e.into_inner())`.
- **Acquire multiple mutexes in a consistent global order** to prevent deadlocks.
- **Use `tokio::sync::Mutex` for locks held across `.await` points.**
- **Never implement `Send`/`Sync` for raw pointer types** without proven thread-safety.

```rust
// ❌ INSECURE — propagates poisoning silently
let data = shared.lock().unwrap();

// ✅ SECURE — handle poisoning explicitly
let data = shared.lock().unwrap_or_else(|p| p.into_inner());

// ✅ SECURE — tokio Mutex for async contexts
let data = shared.lock().await;
```

---

## 12. ReDoS via the `regex` Crate

**Vulnerability:** `fancy-regex` and `pcre2` support backtracking and are vulnerable to ReDoS. The `regex` crate guarantees linear-time matching but `Regex::new()` with user patterns can be expensive.

**References:** CWE-1333, CVE-2022-24713

### Mandatory Rules

- **Use the `regex` crate (not `fancy-regex` or `pcre2`) for user-supplied pattern matching.**
- **Compile fixed regexes with `OnceLock` or `lazy_static!`** — not on every request.
- **Limit input size before matching** to bound execution time.

```rust
// ❌ INSECURE — fancy-regex with user-controlled pattern
let re = fancy_regex::Regex::new(&user_pattern)?;

// ✅ SECURE — pre-compiled regex; linear-time; input size limit
static DATE_RE: OnceLock<regex::Regex> = OnceLock::new();
fn validate_date(input: &str) -> bool {
    if input.len() > 10 { return false; }
    DATE_RE.get_or_init(|| regex::Regex::new(r"^\d{4}-\d{2}-\d{2}$").unwrap()).is_match(input)
}
```

---

## 13. FFI Safety — Calling C/C++ from Rust

**Vulnerability:** FFI bypasses Rust safety guarantees. C code can cause null pointer dereferences, buffer overflows, and ownership confusion.

**References:** CWE-119, CWE-476, CWE-416

### Mandatory Rules

- **Validate all pointers received from C** — check for null before dereferencing.
- **Use `CString`/`CStr` for string interop** — Rust strings are not null-terminated.
- **Match memory ownership explicitly** — use the library's free function for C-allocated memory.
- **Use `bindgen`** for C header bindings and pin its version.

```rust
// ❌ INSECURE — no null check
let slice = unsafe { std::slice::from_raw_parts(data, len) }; // UB if data is null

// ✅ SECURE — null check; CString for interop
fn process(data: *const u8, len: usize) -> Result<(), Error> {
    if data.is_null() { return Err(Error::NullPointer); }
    // SAFETY: data is non-null and valid for `len` bytes.
    let slice = unsafe { std::slice::from_raw_parts(data, len) };
    do_work(slice)
}
```

---

## 14. Web Framework Security (axum, actix-web, warp)

**Vulnerability:** Missing body size limits enable memory exhaustion; permissive CORS exposes data to any origin; missing `SameSite` enables CSRF.

**References:** CWE-352, CWE-16, CWE-400

### Mandatory Rules

- **Set explicit request body size limits** — `DefaultBodyLimit::max()` in axum.
- **Configure CORS allowlists explicitly** — never `CorsLayer::permissive()` in production.
- **Set `SameSite=Strict` on session cookies.**
- **Add security headers** via middleware layer on every response.
- **Use rate limiting middleware** on auth and sensitive endpoints.

```rust
// ❌ INSECURE — permissive CORS, no body limit
let app = Router::new().route("/api/data", get(handler)).layer(CorsLayer::permissive());

// ✅ SECURE — explicit CORS, body limit, security headers
let app = Router::new()
    .route("/api/data", get(handler))
    .layer(DefaultBodyLimit::max(1 * 1024 * 1024))
    .layer(CorsLayer::new().allow_origin("https://app.example.com".parse::<HeaderValue>()?));
```

---

## 15. Logging and Sensitive Data Exposure

**Vulnerability:** Logging `Authorization`/`Cookie` headers, passwords, tokens, or PII exposes secrets to log aggregation systems.

**References:** CWE-532, CWE-209

### Mandatory Rules

- **Never log `Authorization`, `Cookie`, passwords, tokens, or PII.**
- **Use `secrecy::Secret<T>`** for sensitive fields — `Debug` prints `"[redacted]"`.
- **Use `tracing::instrument` with `skip()`** for sensitive function parameters.
- **Return generic error messages to clients** — log details server-side only.

```rust
// ❌ INSECURE — logs password
tracing::info!("Login: user={}, password={}", username, password);

// ✅ SECURE
use secrecy::Secret;
struct LoginRequest { username: String, password: Secret<String> }
#[tracing::instrument(skip(password, db))]
async fn authenticate(username: &str, password: &str, db: &Pool) -> Result<User, Error> { ... }
```

---

## 16. Supply Chain and Dependency Management (Cargo, RustSec, cargo-deny)

**Vulnerability:** Abandoned crates, typosquatting, undisclosed `unsafe`, and known CVEs in transitive dependencies are real risks in the Rust ecosystem.

**References:** CWE-1104, RUSTSEC-2021-0072, CVE-2023-49092

### Mandatory Rules

- **Run `cargo audit` in every CI pipeline** — exits non-zero on known vulnerabilities.
- **Commit `Cargo.lock`** for application crates to ensure reproducible builds.
- **Pin security-critical crates** with `=` or `~` in `Cargo.toml`.
- **Use `cargo-deny`** with `deny.toml` to enforce licenses, banned crates, and advisories.
- **Audit `unsafe` in new dependencies** with `cargo-geiger`.

```toml
# ✅ SECURE — pinned security-critical crates
[dependencies]
rustls = "=0.23.5"
ring = "=0.17.8"
jsonwebtoken = "~9.3"
```

---

## CVE Reference Table

| CVE / Advisory | Severity | Component | Description | Fixed In |
|----------------|----------|-----------|-------------|----------|
| CVE-2022-21658 | High (7.3) | `std::fs::remove_dir_all` | TOCTOU race on Windows allows privilege escalation via symlink substitution | Rust 1.58.1 |
| CVE-2022-24713 | High (7.5) | `regex` ≤ 1.5.5 | ReDoS via alternation causes exponential backtracking in `regex-syntax` | regex 1.5.5 |
| CVE-2022-23639 | High (8.1) | `crossbeam-utils` ≤ 0.8.6 | Unsound `Send`/`Sync` on `AtomicCell<T>` allows data races | crossbeam-utils 0.8.7 |
| CVE-2023-26964 | High (7.5) | `h2` ≤ 0.3.15 | HTTP/2 RST_STREAM flood (Rapid Reset) causes CPU exhaustion | h2 0.3.16 |
| CVE-2023-43669 | High (7.5) | `tungstenite` ≤ 0.20.0 | WebSocket large headers cause stack overflow | tungstenite 0.20.1 |
| CVE-2023-49092 | Medium (5.9) | `rsa` ≤ 0.9.6 | Timing side-channel in RSA PKCS#1 v1.5 (Marvin Attack) | rsa 0.9.7 |
| CVE-2024-32650 | High (7.5) | `rustls` ≤ 0.23.4 | Infinite loop on certain TLS `ClientHello` messages | rustls 0.23.5 |
| CVE-2024-27308 | Medium (5.3) | `mio` ≤ 0.8.10 | Token overflow in I/O event polling allows event injection | mio 0.8.11 |
| RUSTSEC-2021-0072 | Medium (5.9) | `sodiumoxide` ≤ 0.2.6 | Timing side-channel in Ed25519 signature verification | sodiumoxide 0.2.7 |
| RUSTSEC-2021-0003 | Critical (9.8) | `smallvec` ≤ 1.6.0 | Integer overflow in `insert_many` leads to heap buffer overflow | smallvec 1.6.1 |

---

## Security Checklist

### `unsafe` Code
- [ ] Every `unsafe` block has a `// SAFETY:` comment
- [ ] `unsafe` is encapsulated with a safe public API
- [ ] `Send`/`Sync` not implemented manually without proof
- [ ] `cargo-geiger` run before merging dependency updates

### Integer Arithmetic
- [ ] Allocation sizes use `checked_mul`/`checked_add`
- [ ] Casts use `TryFrom`/`TryInto` in security-sensitive paths
- [ ] `[profile.release] overflow-checks = true` evaluated

### Injection
- [ ] No `Command::new("sh").arg("-c")` with user input
- [ ] All SQL uses parameterized placeholders
- [ ] No `format!` building SQL strings

### File System
- [ ] Paths canonicalized and checked against base directory
- [ ] `tempfile::NamedTempFile` used for temp files

### Deserialization
- [ ] `bincode`/`postcard` only on trusted data
- [ ] `serde_json` input size-limited
- [ ] `#[serde(deny_unknown_fields)]` on external structs

### Cryptography
- [ ] `OsRng`/`SystemRandom` for key/nonce generation
- [ ] AES-GCM nonces unique and random
- [ ] MACs compared with `subtle::ConstantTimeEq`
- [ ] `argon2`/`bcrypt` for password hashing
- [ ] Key material in `Zeroizing<_>`

### TLS and HTTP Clients
- [ ] No `danger_accept_invalid_certs(true)`
- [ ] `rustls` preferred; rustls ≥ 0.23.5
- [ ] Timeouts on all HTTP clients

### SSRF
- [ ] User URLs validated for scheme, host, resolved IP
- [ ] Private/loopback IPs blocked
- [ ] Redirects disabled for user-supplied URLs

### Panic Safety
- [ ] No `.unwrap()` in request-handling paths
- [ ] Slice access uses `.get()` for untrusted indices
- [ ] Tokio tasks handle `JoinError`

### Web Frameworks
- [ ] Body size limits configured
- [ ] CORS allowlist (no permissive mode)
- [ ] Session cookies: `SameSite=Strict`, `HttpOnly`, `Secure`
- [ ] Security headers via middleware

### Logging
- [ ] No passwords/tokens/PII logged
- [ ] Sensitive fields use `secrecy::Secret<T>`
- [ ] `tracing::instrument` uses `skip()` for sensitive params

### Supply Chain
- [ ] `cargo audit` in CI
- [ ] `Cargo.lock` committed for app crates
- [ ] `cargo-deny` configured
- [ ] Security-critical crates pinned with `=` or `~`

---

## Tooling

| Tool | Purpose | Command |
|------|---------|---------|
| [cargo-audit](https://github.com/rustsec/rustsec/tree/main/cargo-audit) | Checks `Cargo.lock` against RustSec advisory database | `cargo audit` |
| [cargo-deny](https://github.com/EmbarkStudios/cargo-deny) | License compliance, banned crates, advisory enforcement | `cargo deny check` |
| [cargo-geiger](https://github.com/geiger-rs/cargo-geiger) | Counts `unsafe` usage in crate and all dependencies | `cargo geiger` |
| [cargo-vet](https://github.com/mozilla/cargo-vet) | Supply-chain auditing — tracks audited crates | `cargo vet` |
| [clippy](https://github.com/rust-lang/rust-clippy) | Linter with security-relevant lints | `cargo clippy -- -D warnings` |
| [cargo-fuzz](https://github.com/rust-fuzz/cargo-fuzz) | LibFuzzer-based fuzzing for panics and memory issues | `cargo fuzz run fuzz_target_1` |
| [semgrep (Rust)](https://semgrep.dev/r?lang=rust) | Static analysis for Rust security anti-patterns | `semgrep --config=r/rust.lang.security .` |
