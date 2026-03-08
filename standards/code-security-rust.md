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

// ❌ INSECURE — no SAFETY comment; borrow checker bypassed silently
unsafe {
    let reference: &str = std::mem::transmute(bytes);
    process(reference);
}

// ✅ SECURE — alignment verified; invariant documented
assert!(data.as_ptr() as usize % std::mem::align_of::<u64>() == 0, "misaligned");
// SAFETY: `data` has been verified to be 8-byte aligned and contains
// at least 8 initialized bytes at this point.
let val = unsafe { std::ptr::read_unaligned(data.as_ptr() as *const u64) };

// ✅ SECURE — bytemuck provides safe transmutation with compile-time layout checks
use bytemuck::Pod;
let val: u64 = bytemuck::from_bytes(&data[..8]).clone();
```

---

## 2. Integer Overflow and Arithmetic Safety

**Vulnerability:** In Rust release builds, integer arithmetic wraps on overflow by default (unlike debug builds, which panic). Overflow in allocation sizes (`len * size_of::<T>()`) leads to under-allocated buffers and heap corruption. Overflow in index calculations causes out-of-bounds access. Truncating casts (`u64 as u32`, `usize as u8`) silently discard high bits.

**References:** CWE-190, CWE-191, CWE-195, RUSTSEC-2021-0003 (smallvec)

### Mandatory Rules

- **Use `checked_add`/`checked_mul`/`checked_sub`** for arithmetic that feeds into allocation sizes, buffer indices, or security-sensitive calculations — return an error on overflow rather than wrapping.
- **Use `saturating_*` arithmetic** only for non-security metrics (counters, UI values) where saturation is a safe bound; never for buffer sizes.
- **Avoid as-casts between integer types** in security-sensitive paths — use `TryFrom`/`TryInto` to return an error on truncation.
- **Enable `overflow-checks = true` in `[profile.release]`** for production binaries where performance permits — this enables overflow panics in release builds.
- **Never multiply untrusted lengths by element sizes without overflow checking** before passing to allocation functions.

```rust
// ❌ INSECURE — release build wraps: count=0x4000_0001, elem=8 → allocates 8 bytes
let buf: Vec<u8> = Vec::with_capacity(count * elem_size);

// ❌ INSECURE — silent truncation: offset=0x1_0000_0001 → index=1 on 32-bit
let index = offset as u32;
data[index as usize] = value;

// ✅ SECURE — checked multiplication; returns error on overflow
let capacity = count
    .checked_mul(elem_size)
    .ok_or(Error::Overflow)?;
let buf: Vec<u8> = Vec::with_capacity(capacity);

// ✅ SECURE — TryFrom returns Err on truncation
let index = u32::try_from(offset).map_err(|_| Error::IndexOutOfRange)?;
data[index as usize] = value;
```

---

## 3. Command Injection via `std::process::Command`

**Vulnerability:** Passing user-controlled input to `Command::new("sh").arg("-c").arg(userInput)` or building shell strings interprets shell metacharacters (`;`, `|`, `$()`, backticks), executing attacker-controlled commands. Letting the user control the binary name (`Command::new(user_binary)`) lets them execute any accessible binary.

**References:** CWE-78

### Mandatory Rules

- **Never use shell forms** — `Command::new("sh").arg("-c").arg(user_input)` passes input through a shell interpreter; use `Command::new("binary")` with separate `.arg()` calls so the OS passes arguments directly to `execve`.
- **Never let user input control the binary name** (first argument to `Command::new`) — allowlist the binary path at compile time.
- **Validate and allowlist all user-supplied arguments** before adding them with `.arg()` — even without a shell, a malicious argument to certain binaries (`rsync --rsh`, `git -c core.sshCommand=`) can cause harm.
- **Use `Command::output()`/`Command::status()` with explicit timeouts** via `tokio::time::timeout` or `std::thread` to prevent resource exhaustion from long-running child processes.
- **Capture and sanitize child process output** before logging or returning to callers — child processes may echo back attacker-controlled input.

```rust
// ❌ INSECURE — shell interprets metacharacters; filename = "foo; rm -rf /"
let output = Command::new("sh")
    .arg("-c")
    .arg(format!("grep {} /var/log/app.log", filename))
    .output()?;

// ❌ INSECURE — user controls binary name
let output = Command::new(&user_supplied_program).output()?;

// ✅ SECURE — argument array; OS passes directly to execve, no shell expansion
let output = Command::new("/usr/bin/grep")
    .arg("--")
    .arg(&filename)          // validated: contains only printable non-metachar chars
    .arg("/var/log/app.log")
    .output()?;
```

---

## 4. SQL Injection via Diesel, SQLx, and SeaORM

**Vulnerability:** String interpolation or concatenation in raw SQL queries enables SQL injection. While Diesel's type-safe query builder prevents most injection at compile time, raw SQL escape hatches (`diesel::sql_query`, `sqlx::query!` with format strings, `sea_orm::Statement::from_string`) bypass protection entirely.

**References:** CWE-89

### Mandatory Rules

- **Prefer Diesel's type-safe query builder** (`diesel::QueryDsl`) over raw SQL — the builder parameterizes all values at the driver level.
- **When using `diesel::sql_query` or `sqlx::query`/`query!`, always bind all user-controlled values via `.bind()`/`$1` placeholders** — never interpolate them into the query string.
- **In SeaORM, use `sea_query::Expr::val()` or `sea_query::Value`** bindings; never construct `Statement::from_string` with format! containing user data.
- **Allowlist ORDER BY column names and directions** — SQL column names and keywords cannot be parameterized; validate against a hardcoded set before interpolating.
- **In SQLx, prefer the `query!` macro** (compile-time query checking) over `query()` with runtime strings — it provides type checking and prevents accidental interpolation.

```rust
// ❌ INSECURE — SQL injection via format!; email = "' OR '1'='1"
let q = format!("SELECT * FROM users WHERE email = '{}'", email);
diesel::sql_query(q).execute(&mut conn)?;

// ❌ INSECURE — sqlx with format string
let rows = sqlx::query(&format!("SELECT id FROM users WHERE name = '{}'", name))
    .fetch_all(&pool)
    .await?;

// ✅ SECURE — Diesel type-safe query builder (compile-time checked)
use schema::users::dsl::*;
let user = users.filter(email.eq(&user_email)).first::<User>(&mut conn)?;

// ✅ SECURE — SQLx with bind parameter
let rows = sqlx::query("SELECT id FROM users WHERE name = $1")
    .bind(&name)
    .fetch_all(&pool)
    .await?;

// ✅ SECURE — diesel::sql_query with explicit bind
diesel::sql_query("SELECT * FROM logs WHERE level = $1")
    .bind::<diesel::sql_types::Text, _>(&level)
    .load::<Log>(&mut conn)?;
```

---

## 5. Path Traversal and File System Operations

**Vulnerability:** Accepting user-controlled file paths without canonicalization allows traversal outside the intended directory (`../../etc/passwd`). `std::fs::File::open(user_path)` resolves symlinks and `..` components, so prefixing with a base directory is insufficient without canonicalization. `std::fs::remove_dir_all` was vulnerable to a TOCTOU race (CVE-2022-21658) on Windows prior to Rust 1.58.1.

**References:** CWE-22, CWE-377, CVE-2022-21658

### Mandatory Rules

- **Canonicalize both the base directory and the user-supplied path** with `std::fs::canonicalize()`, then verify the result starts with the canonicalized base — this resolves `..`, symlinks, and redundant separators.
- **Never use `Path::join(user_input)` as the sole guard** — `Path::new("/safe/base").join("/etc/passwd")` silently discards the base when the user input is absolute.
- **Reject paths containing null bytes** — Rust's `std::fs` functions will return an error, but explicitly validate before any other processing.
- **Update to Rust ≥ 1.58.1** to get the TOCTOU fix for `remove_dir_all` (CVE-2022-21658); prefer `std::fs::remove_dir_all` over manual recursive deletion.
- **Use `tempfile::NamedTempFile`** instead of constructing temporary file paths manually — `tmpnam`-style patterns are vulnerable to TOCTOU.

```rust
// ❌ INSECURE — traversal: user_path = "../../etc/shadow"
let path = Path::new("/srv/uploads").join(&user_path);
let content = fs::read_to_string(&path)?;

// ❌ INSECURE — absolute path discards base: user_path = "/etc/passwd"
let path = base_dir.join(&user_path); // result = /etc/passwd

// ✅ SECURE — canonicalize both, then verify prefix
let base = fs::canonicalize("/srv/uploads")?;
let target = fs::canonicalize(base.join(&user_path))?;
if !target.starts_with(&base) {
    return Err(Error::PathTraversal);
}
let content = fs::read_to_string(&target)?;
```

---

## 6. Deserialization Security (serde, bincode, ciborium, postcard)

**Vulnerability:** Deserializing untrusted binary data with `bincode`/`ciborium`/`postcard` can trigger stack overflows via deeply nested structures, heap exhaustion via large collection sizes, or memory unsafety in crates with `unsafe` deserialization paths. `serde_json` with `serde_json::Value` and untrusted input can consume unbounded memory on deeply nested JSON.

**References:** CWE-502, CWE-400

### Mandatory Rules

- **Never use `bincode` on data from untrusted external sources** without strict size limits and a schema version check — `bincode` has no built-in depth or size limits.
- **Limit JSON nesting depth** when using `serde_json` with untrusted input — wrap the reader in a depth-limiting deserializer or validate document size before parsing.
- **Use `#[serde(deny_unknown_fields)]`** on structs that accept external data — this rejects unexpected fields that could indicate format confusion or data injection.
- **Avoid `serde_json::from_reader` on unbounded streams** — read into a size-limited buffer first, then deserialize.
- **Prefer schema-validated formats** (JSON with JSON Schema, Protocol Buffers, Avro) for external data; use binary formats only for internal trusted communication.
- **Pin deserialization crate versions and audit them with `cargo audit`** — memory-safety bugs in `unsafe` deserialization code are a common advisory source.

```rust
// ❌ INSECURE — bincode on untrusted network bytes; unbounded allocation
let msg: MyMessage = bincode::deserialize(&network_bytes)?;

// ❌ INSECURE — unbounded JSON reader on untrusted HTTP body
let value: serde_json::Value = serde_json::from_reader(request.body())?;

// ✅ SECURE — read with explicit size limit before deserializing
const MAX_BODY: usize = 1 * 1024 * 1024; // 1 MiB
let mut body = Vec::with_capacity(4096);
request.body_mut().read_to_limit(&mut body, MAX_BODY)?;
let value: MyStruct = serde_json::from_slice(&body)?;

// ✅ SECURE — reject unknown fields from external callers
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CreateUserRequest {
    username: String,
    email: String,
}
```

---

## 7. Cryptography Misuse (ring, RustCrypto, rand)

**Vulnerability:** Using `rand::thread_rng()` (PRNG seeded from OS entropy but not cryptographically suitable for long-lived keys), reusing nonces with AES-GCM (catastrophic nonce reuse breaks both confidentiality and authenticity), using deprecated crates (`rust-crypto`, `sodiumoxide` timing vulnerability RUSTSEC-2021-0072), or rolling custom crypto introduces exploitable weaknesses.

**References:** CWE-330, CWE-327, CWE-338, RUSTSEC-2021-0072, CVE-2023-49092

### Mandatory Rules

- **Use `rand::rngs::OsRng` or `ring::rand::SystemRandom`** for all cryptographic key and nonce generation — `thread_rng()` is deterministic and unsuitable for secrets.
- **Generate a unique random 96-bit nonce for every AES-256-GCM encryption operation** — nonce reuse with the same key is catastrophic: it reveals the authentication key and allows decryption.
- **Use `ring` or `RustCrypto` (`aes-gcm`, `chacha20poly1305`) for symmetric encryption** — avoid the unmaintained `rust-crypto` crate and `sodiumoxide` (RUSTSEC-2021-0072 timing side channel).
- **Never implement custom cryptographic primitives** — use `ring`, `RustCrypto`, or `libsodium` via `sodiumoxide` (patched version) bindings.
- **For RSA operations, use `ring` ≥ 0.17 or `rsa` ≥ 0.9.7** — earlier versions of the `rsa` crate had a timing side-channel attack (CVE-2023-49092).
- **Use `argon2` or `bcrypt` from `rust-argon2`/`bcrypt` crates for password hashing** — never use SHA-2 alone for passwords.
- **Use `subtle::ConstantTimeEq`** for comparing MACs, tokens, and other secret byte slices — byte-by-byte comparison leaks timing information.
- **Store private keys in memory using `zeroize::Zeroizing<Vec<u8>>`** to zero out key material when dropped.

```rust
// ❌ INSECURE — thread_rng is not suitable for cryptographic key generation
use rand::Rng;
let key: [u8; 32] = rand::thread_rng().gen();

// ❌ INSECURE — static/reused nonce breaks AES-GCM completely
let nonce = aes_gcm::Nonce::from_slice(b"static_nonce"); // reused every call

// ❌ INSECURE — non-constant-time comparison leaks timing info
if mac_from_request == expected_mac { ... }

// ✅ SECURE — OS entropy for key generation
use rand::rngs::OsRng;
use rand::RngCore;
let mut key = [0u8; 32];
OsRng.fill_bytes(&mut key);

// ✅ SECURE — unique random nonce per encryption
use aes_gcm::{Aes256Gcm, KeyInit, aead::{Aead, OsRng as AeadOsRng, rand_core::RngCore}};
let cipher = Aes256Gcm::new_from_slice(&key)?;
let mut nonce_bytes = [0u8; 12];
OsRng.fill_bytes(&mut nonce_bytes);
let nonce = aes_gcm::Nonce::from_slice(&nonce_bytes);
let ciphertext = cipher.encrypt(nonce, plaintext)?;

// ✅ SECURE — constant-time MAC comparison
use subtle::ConstantTimeEq;
if mac_from_request.ct_eq(&expected_mac).into() { ... }
```

---

## 8. TLS Configuration (rustls, native-tls, reqwest)

**Vulnerability:** Disabling certificate verification (`danger_accept_invalid_certs(true)` in `reqwest`), accepting invalid hostnames, or using weak TLS versions enables man-in-the-middle attacks. `native-tls` inherits system TLS settings which may allow TLS 1.0/1.1 on older systems.

**References:** CWE-295, CWE-326

### Mandatory Rules

- **Never set `danger_accept_invalid_certs(true)` or `danger_accept_invalid_hostnames(true)`** in production `reqwest` clients — these disable all TLS validation.
- **Prefer `rustls` over `native-tls`** for new projects — `rustls` enforces TLS 1.2+ by default and is memory-safe; `native-tls` depends on the platform TLS stack (OpenSSL/SChannel/Secure Transport).
- **Configure `rustls::ClientConfig` with `with_safe_defaults()`** — this applies the rustls security policy (TLS 1.2+, safe cipher suites, certificate verification).
- **Pin certificates for high-value internal services** using `rustls-native-certs` combined with custom `ServerCertVerifier` — pin the CA or leaf certificate fingerprint.
- **Set connection and request timeouts on every HTTP client** — `reqwest::ClientBuilder` with `.timeout(Duration::from_secs(30))` prevents Slowloris-style resource exhaustion.

```rust
// ❌ INSECURE — disables all TLS certificate validation
let client = reqwest::Client::builder()
    .danger_accept_invalid_certs(true)
    .build()?;

// ❌ INSECURE — no timeout; vulnerable to Slowloris
let client = reqwest::Client::new();

// ✅ SECURE — rustls with safe defaults, no certificate bypasses, timeout set
let client = reqwest::Client::builder()
    .use_rustls_tls()
    .timeout(std::time::Duration::from_secs(30))
    .build()?;
```

---

## 9. SSRF and HTTP Client Security (reqwest, hyper)

**Vulnerability:** Passing user-supplied URLs directly to `reqwest::get(user_url)` allows an attacker to reach internal services (cloud metadata endpoints `169.254.169.254`, Redis, database ports) or perform port scans. Rust's async HTTP clients follow redirects by default, which can be chained to bypass URL validation performed before the request.

**References:** CWE-918

### Mandatory Rules

- **Never pass user-supplied URLs directly to `reqwest::get()` or `Client::request()`** without strict URL validation.
- **Validate the scheme** — only permit `https://` (and `http://` if explicitly required); reject `file://`, `ftp://`, `gopher://`, and other schemes.
- **Resolve the hostname to an IP address and validate the IP** against a blocklist before making the request — block private (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`), loopback (`127.0.0.0/8`, `::1`), link-local (`169.254.0.0/16`), and multicast ranges.
- **Limit redirects or disable them** when making requests with user-supplied URLs — `.redirect(reqwest::redirect::Policy::none())`.
- **Use allowlists of permitted hostnames** whenever possible instead of blocklists — blocklists are bypassable via DNS rebinding or alternative IP representations.

```rust
// ❌ INSECURE — SSRF: user_url = "http://169.254.169.254/latest/meta-data/"
let response = reqwest::get(&user_url).await?;

// ✅ SECURE — scheme check + IP validation + redirect disabled
fn validate_url(url: &str) -> Result<url::Url, Error> {
    let parsed = url::Url::parse(url)?;
    if parsed.scheme() != "https" {
        return Err(Error::InvalidScheme);
    }
    // Resolve and validate IP (use `dns-lookup` + `ipnetwork` crates)
    let host = parsed.host_str().ok_or(Error::MissingHost)?;
    for addr in dns_lookup::lookup_host(host)? {
        if is_private_or_loopback(&addr) {
            return Err(Error::PrivateIpBlocked);
        }
    }
    Ok(parsed)
}

let url = validate_url(&user_url)?;
let client = reqwest::Client::builder()
    .redirect(reqwest::redirect::Policy::none())
    .timeout(std::time::Duration::from_secs(10))
    .build()?;
let response = client.get(url).send().await?;
```

---

## 10. Panic Safety — `unwrap`/`expect` DoS Prevention

**Vulnerability:** Calling `.unwrap()` or `.expect()` on `Option::None` or `Err(e)` panics the current thread. In Tokio async runtimes, a panic in a task is caught by the runtime but terminates the task; in a `spawn_blocking` context or synchronous context, it can crash the process. Attackers can trigger panics through crafted input (e.g., integer parsing, array indexing) to cause denial of service.

**References:** CWE-390, CWE-248

### Mandatory Rules

- **Never use `.unwrap()` on `Option` or `Result` in request-handling code paths** — propagate errors with `?` or handle them explicitly.
- **Use `expect()` only for invariants that are truly impossible to violate** (e.g., after a preceding `is_some()` check), and document why in the expect message.
- **Use `get()` and `get_mut()` instead of direct index access (`slice[i]`)** on untrusted indices — direct indexing panics on out-of-bounds.
- **In Tokio, wrap top-level task logic in `catch_unwind`** or use `tokio::spawn` with `.await` and handle `JoinError` — an unhandled panic in a task kills only that task.
- **Parse integers with `str::parse::<T>()` and `?`** rather than calling `.unwrap()` on the result.
- **Prefer `checked_*` arithmetic over relying on `#[cfg(debug_assertions)]`** panics — panics in debug builds become silent wrapping in release builds by default.

```rust
// ❌ INSECURE — panics if query param is missing or not a valid integer
let id: i32 = params.get("id").unwrap().parse().unwrap();

// ❌ INSECURE — panics on out-of-bounds index from user input
let item = items[user_index];

// ✅ SECURE — propagate errors; no panic path
let id: i32 = params
    .get("id")
    .ok_or(Error::MissingParam("id"))?
    .parse()
    .map_err(|_| Error::InvalidParam("id"))?;

// ✅ SECURE — bounds-checked access
let item = items
    .get(user_index)
    .ok_or(Error::IndexOutOfBounds)?;
```

---

## 11. Concurrency Safety — Data Races in `unsafe`, Deadlocks, and Poisoned Mutexes

**Vulnerability:** Rust's type system prevents data races in safe code, but `unsafe` implementations of `Send`/`Sync` can introduce races. `Mutex::lock()` returns a `LockResult` that is `Err` when the mutex is poisoned (previous lock holder panicked); calling `.unwrap()` on it propagates poisoning silently. Holding multiple locks in inconsistent order causes deadlocks.

**References:** CWE-362, CWE-833, CVE-2022-23639 (crossbeam-utils)

### Mandatory Rules

- **Handle mutex poisoning explicitly** — call `.lock().unwrap_or_else(|e| e.into_inner())` when safe to continue with potentially partially-modified state, or propagate the error.
- **Always acquire multiple mutexes in a consistent global order** — document lock ordering; use a lock hierarchy (e.g., always lock A before B) to prevent deadlocks.
- **Prefer `RwLock` for read-heavy shared state**, but ensure writers are not starved; on Linux, `std::sync::RwLock` can starve writers.
- **Use `tokio::sync::Mutex` for locks held across `.await` points** — `std::sync::Mutex` held across an `.await` causes a compile error (`!Send`), which is the correct guard; do not work around it.
- **Do not implement `Send` or `Sync` for types containing raw pointers** unless you have proven thread-safety manually; use `PhantomData<*mut T>` to opt out.
- **Audit dependencies for unsound `Send`/`Sync` implementations** — this was the root cause of CVE-2022-23639 (crossbeam-utils).

```rust
// ❌ INSECURE — propagates poisoning silently; data may be inconsistent
let data = shared.lock().unwrap();

// ❌ INSECURE — std::sync::Mutex held across await (compile error, but watch for workarounds)
let guard = mutex.lock().unwrap();
do_async_work().await; // guard held across await: not Send

// ✅ SECURE — handle poisoning; decide whether to recover or propagate
let data = shared.lock().unwrap_or_else(|poisoned| {
    log::warn!("Mutex was poisoned; recovering state");
    poisoned.into_inner()
});

// ✅ SECURE — tokio Mutex for async contexts
use tokio::sync::Mutex;
let data = shared.lock().await; // properly held across .await
```

---

## 12. ReDoS via the `regex` Crate

**Vulnerability:** The `regex` crate uses a finite automaton engine that guarantees linear-time matching (`O(n)` in input length) for all patterns — it **does not** support lookaheads, backreferences, or other exponential-time features. However, `fancy-regex` and `pcre2` crates support backtracking and **are** vulnerable to ReDoS. Patterns with user-controlled input fed into `Regex::new()` at runtime can trigger panics or extremely long compile times.

**References:** CWE-1333, CVE-2022-24713

### Mandatory Rules

- **Use the `regex` crate (not `fancy-regex` or `pcre2`) for user-supplied pattern matching** — its linear-time guarantee prevents ReDoS.
- **Never compile user-supplied patterns with `fancy-regex::Regex::new()`** — it supports backreferences and lookaheads that can cause catastrophic backtracking.
- **Compile all fixed (developer-authored) regexes at startup with `lazy_static!` or `std::sync::OnceLock`** — repeated `Regex::new()` calls on hot paths are expensive but not a security issue for fixed patterns.
- **Limit input size before matching** — even with a linear-time engine, extremely large inputs consume proportional time; set a maximum input length before calling `is_match()`.
- **Set `Regex::new()` size limit** via `regex::RegexBuilder::new().size_limit(1_000_000)` when the pattern itself comes from semi-trusted sources.

```rust
// ❌ INSECURE — fancy-regex with user-controlled pattern: catastrophic backtracking
let re = fancy_regex::Regex::new(&user_pattern)?;
let matched = re.is_match(&input)?;

// ❌ INSECURE — recompiling regex on every request (performance issue)
let re = regex::Regex::new(r"^\d{4}-\d{2}-\d{2}$").unwrap();

// ✅ SECURE — pre-compiled regex; linear-time engine; input size limit
use std::sync::OnceLock;
static DATE_RE: OnceLock<regex::Regex> = OnceLock::new();

fn validate_date(input: &str) -> bool {
    if input.len() > 10 { return false; } // length guard
    DATE_RE
        .get_or_init(|| regex::Regex::new(r"^\d{4}-\d{2}-\d{2}$").unwrap())
        .is_match(input)
}
```

---

## 13. FFI Safety — Calling C/C++ from Rust

**Vulnerability:** Rust code that calls C/C++ via FFI enters `unsafe` territory where the C code can cause use-after-free, null pointer dereferences, buffer overflows, or pass invalid pointers back. Ownership and lifetime are not enforced across the FFI boundary.

**References:** CWE-119, CWE-476, CWE-416

### Mandatory Rules

- **Encapsulate all FFI calls within `unsafe` blocks and wrap them in a safe Rust API** — callers should never need to write `unsafe` to use your FFI wrapper.
- **Validate all pointers received from C before dereferencing** — check for null pointers before calling methods on them.
- **Never pass Rust references (`&T`, `&mut T`) to C functions expecting raw pointers** without ensuring the C side does not store the pointer beyond the function call.
- **Use `CString`/`CStr` for string interop** — never pass a `&str` or `String` directly; C expects null-terminated strings and Rust strings are not null-terminated.
- **Match memory ownership explicitly** — if C allocates memory and expects the caller to free it, use the C `free` function (or the library's free function), not Rust's allocator.
- **Use `bindgen` for C header bindings** and pin the version; manually-written bindings are error-prone for types with alignment or size differences.

```rust
// ❌ INSECURE — no null check; dereferences potentially null C pointer
extern "C" fn process(data: *const u8, len: usize) {
    let slice = unsafe { std::slice::from_raw_parts(data, len) }; // UB if data is null
}

// ❌ INSECURE — Rust string passed where C string expected (no null terminator)
unsafe { c_lib::set_name(rust_string.as_ptr()) };

// ✅ SECURE — null check before dereferencing; CString for interop
fn process(data: *const u8, len: usize) -> Result<(), Error> {
    if data.is_null() { return Err(Error::NullPointer); }
    // SAFETY: data is non-null and valid for `len` bytes (caller invariant).
    let slice = unsafe { std::slice::from_raw_parts(data, len) };
    do_work(slice)
}

let c_name = CString::new(rust_name)?; // returns Err if interior null
unsafe { c_lib::set_name(c_name.as_ptr()) };
```

---

## 14. Web Framework Security (axum, actix-web, warp)

**Vulnerability:** Axum, actix-web, and warp have different default behaviors for body limits, CORS, header handling, and session management. Missing CORS configuration allows cross-origin requests; missing body size limits enable memory exhaustion; unvalidated Content-Type enables type confusion attacks; and missing `SameSite` on session cookies enables CSRF.

**References:** CWE-352, CWE-16, CWE-400

### Mandatory Rules

- **Set an explicit request body size limit** — axum uses `DefaultBodyLimit::max(bytes)` layer; actix-web uses `web::JsonConfig::default().limit()` — the default in actix-web is 256 KiB but may be changed.
- **Configure CORS allowlists explicitly** — never use `CorsLayer::permissive()` or `Cors::permissive()` in production; specify exact allowed origins, methods, and headers.
- **Set `SameSite=Strict` or `SameSite=Lax` on session cookies** — use the `cookie` crate with `.same_site(SameSite::Strict)`.
- **Validate `Content-Type` before deserializing request bodies** — axum's `Json` extractor validates `Content-Type: application/json`; actix-web's `web::Json` does the same, but `web::Bytes` bypasses this.
- **Add security headers** (`X-Frame-Options`, `X-Content-Type-Options`, `Strict-Transport-Security`) via a middleware layer on every response.
- **Use rate limiting middleware** (`tower_governor`, `actix-governor`) on authentication, registration, and password-reset endpoints.
- **Never log raw request bodies** that may contain credentials, tokens, or PII — log sanitized summaries.

```rust
// ❌ INSECURE — permissive CORS allows any origin to read responses
use tower_http::cors::CorsLayer;
let app = Router::new()
    .route("/api/data", get(handler))
    .layer(CorsLayer::permissive()); // all origins, all methods

// ❌ INSECURE — no body size limit; memory exhaustion via large upload
let app = Router::new().route("/upload", post(upload_handler));

// ✅ SECURE — axum with explicit CORS, body limit, security headers
use axum::extract::DefaultBodyLimit;
use tower_http::{cors::CorsLayer, set_header::SetResponseHeaderLayer};
use http::{header, HeaderValue, Method};

let cors = CorsLayer::new()
    .allow_origin("https://app.example.com".parse::<HeaderValue>()?)
    .allow_methods([Method::GET, Method::POST])
    .allow_credentials(true);

let app = Router::new()
    .route("/api/data", get(handler))
    .layer(DefaultBodyLimit::max(1 * 1024 * 1024)) // 1 MiB
    .layer(cors)
    .layer(SetResponseHeaderLayer::overriding(
        header::X_CONTENT_TYPE_OPTIONS,
        HeaderValue::from_static("nosniff"),
    ));
```

---

## 15. Logging and Sensitive Data Exposure

**Vulnerability:** Logging request parameters, headers (including `Authorization`, `Cookie`), database query results, or internal error messages containing file paths or PII with `tracing`/`log` macros exposes sensitive data to log aggregation systems, log files, and monitoring dashboards.

**References:** CWE-532, CWE-209

### Mandatory Rules

- **Never log `Authorization`, `Cookie`, `X-API-Key` headers** — when logging request headers, use an explicit allowlist of safe header names.
- **Never log passwords, tokens, session identifiers, PII, or private keys** — use redacted structs with custom `Debug`/`Display` implementations.
- **Use `tracing::instrument` with `skip(password, token)`** to exclude sensitive fields from span attributes.
- **Return generic error messages to clients** — log detailed internal errors (including file paths and stack traces) server-side only; never return them in HTTP responses.
- **Redact sensitive fields in structs** using `secrecy::Secret<T>` (from the `secrecy` crate) — `Secret<String>` implements `Debug` as `"[redacted]"` by default.
- **Enable structured logging** (`tracing-subscriber` with JSON output) and configure PII scrubbing in your log aggregation pipeline.

```rust
// ❌ INSECURE — logs user password and token
tracing::info!("Login attempt: user={}, password={}, token={}", username, password, token);

// ❌ INSECURE — logs full Authorization header
tracing::debug!("Request headers: {:?}", request.headers());

// ✅ SECURE — secrecy crate redacts Secret<T> in Debug output
use secrecy::{Secret, ExposeSecret};
struct LoginRequest {
    username: String,
    password: Secret<String>,  // Debug prints "[redacted]"
}
tracing::info!(username = %req.username, "Login attempt");
// password.expose_secret() only when actually needed for hashing

// ✅ SECURE — tracing::instrument skips sensitive fields
#[tracing::instrument(skip(password, db))]
async fn authenticate(username: &str, password: &str, db: &Pool) -> Result<User, Error> {
    // ...
}
```

---

## 16. Supply Chain and Dependency Management (Cargo, RustSec, cargo-deny)

**Vulnerability:** Rust's ecosystem is generally well-maintained but not immune to supply-chain attacks, typosquatting, abandoned crates with known vulnerabilities, and crates with undisclosed `unsafe` usage. The RustSec Advisory Database tracks Rust-specific CVEs and RUSTSEC advisories.

**References:** CWE-1104, RUSTSEC-2021-0072, CVE-2023-49092

### Mandatory Rules

- **Run `cargo audit` in every CI pipeline** — it checks `Cargo.lock` against the RustSec Advisory Database and exits non-zero on known vulnerabilities.
- **Commit `Cargo.lock`** for application crates (not library crates) to ensure reproducible builds and make supply-chain changes visible in code review.
- **Pin critical dependency versions** with `=` or `~` specifiers in `Cargo.toml` for security-sensitive crates (TLS, crypto, auth) — cargo's `^` semver range can automatically adopt new minor versions.
- **Use `cargo-deny`** with an explicit `deny.toml` to enforce: allowed licenses, banned crates, advisory database, and duplicate version detection.
- **Audit `unsafe` usage in new dependencies** with `cargo-geiger` before merging — a sudden spike in `unsafe` code in an update is a red flag.
- **Use `cargo-vet`** (Mozilla's supply-chain auditing tool) for projects with high security requirements — it tracks which crates have been manually audited and by whom.
- **Check crate ownership on crates.io** before adding new dependencies — prefer crates maintained by large organizations or with broad community adoption over single-maintainer crates with recent ownership changes.

```toml
# ✅ SECURE — Cargo.toml with pinned security-critical crates
[dependencies]
rustls = "=0.23.5"          # exact version for TLS
ring = "=0.17.8"            # exact version for crypto
jsonwebtoken = "~9.3"       # patch updates only for JWT

# ✅ SECURE — deny.toml (cargo-deny configuration)
# [advisories]
# db-path = "~/.cargo/advisory-db"
# db-urls = ["https://github.com/rustsec/advisory-db"]
# vulnerability = "deny"
# unmaintained = "warn"
# yanked = "deny"
#
# [bans]
# multiple-versions = "warn"
# deny = [
#   { name = "sodiumoxide", version = "<0.2.7" },  # timing vulnerability
# ]
```

---

## CVE Reference Table

| CVE / Advisory | Severity | Component | Description | Fixed In |
|----------------|----------|-----------|-------------|----------|
| CVE-2022-21658 | High (7.3) | `std::fs::remove_dir_all` (Rust stdlib) | TOCTOU race condition on Windows allows privilege escalation via symlink substitution during recursive directory removal | Rust 1.58.1 |
| CVE-2022-24713 | High (7.5) | `regex` ≤ 1.5.5 | ReDoS via specially crafted pattern with alternation causes exponential backtracking in `regex-syntax` | regex 1.5.5 / regex-syntax 0.6.26 |
| CVE-2022-23639 | High (8.1) | `crossbeam-utils` ≤ 0.8.6 | Unsound `Send`/`Sync` implementation on `AtomicCell<T>` allows data races on types that are not `Copy` | crossbeam-utils 0.8.7 |
| CVE-2023-26964 | High (7.5) | `h2` ≤ 0.3.15 (used by hyper/reqwest) | HTTP/2 RST_STREAM flood (Rapid Reset Attack) causes CPU exhaustion — server spends time on frames for reset streams | h2 0.3.16, hyper 0.14.27 |
| CVE-2023-43669 | High (7.5) | `tungstenite` ≤ 0.20.0 | WebSocket handshake with excessively large headers causes stack overflow in the header parser | tungstenite 0.20.1 |
| CVE-2023-49092 | Medium (5.9) | `rsa` ≤ 0.9.6 | Timing side-channel in RSA PKCS#1 v1.5 decryption allows partial private key recovery (Marvin Attack) | rsa 0.9.7 |
| CVE-2024-32650 | High (7.5) | `rustls` ≤ 0.23.4 | Infinite loop when processing certain TLS `ClientHello` messages causes denial of service | rustls 0.23.5 |
| CVE-2024-27308 | Medium (5.3) | `mio` ≤ 0.8.10 | Token value overflow in I/O event polling on Windows allows event injection or DoS | mio 0.8.11 |
| RUSTSEC-2021-0072 | Medium (5.9) | `sodiumoxide` ≤ 0.2.6 | Timing side-channel in `crypto_sign_ed25519_verify_detached` may allow signature forgery | sodiumoxide 0.2.7 |
| RUSTSEC-2021-0003 | Critical (9.8) | `smallvec` ≤ 1.6.0 | Integer overflow in `insert_many` leads to heap buffer overflow and potential arbitrary code execution | smallvec 1.6.1 |

---

## Security Checklist

### `unsafe` Code
- [ ] Every `unsafe` block has a `// SAFETY:` comment explaining the invariants
- [ ] `unsafe` is encapsulated in a small module with a safe public API
- [ ] `Send`/`Sync` are not implemented manually without proof of thread-safety
- [ ] `cargo-geiger` is run before merging dependency updates

### Integer Arithmetic
- [ ] Allocation sizes computed with `checked_mul`/`checked_add`
- [ ] Numeric casts use `TryFrom`/`TryInto` in security-sensitive paths
- [ ] `[profile.release] overflow-checks = true` evaluated for production

### Injection
- [ ] No `Command::new("sh").arg("-c")` with user input
- [ ] All SQL queries use parameterized placeholders via Diesel/SQLx/SeaORM
- [ ] No `format!` used to build SQL strings

### File System
- [ ] All user-supplied paths are canonicalized and checked against a base directory
- [ ] `Path::join` is never the sole traversal guard
- [ ] `tempfile::NamedTempFile` used for temporary files

### Deserialization
- [ ] Binary deserialization (`bincode`, `postcard`) only on trusted internal data
- [ ] `serde_json` input size-limited before parsing
- [ ] `#[serde(deny_unknown_fields)]` applied to external-facing structs

### Cryptography
- [ ] `OsRng` or `ring::rand::SystemRandom` used for all key/nonce generation
- [ ] AES-GCM nonces are unique and random (not static or counter-based without careful analysis)
- [ ] MACs compared with `subtle::ConstantTimeEq`
- [ ] `argon2`/`bcrypt` used for password hashing (not SHA-2 alone)
- [ ] Key material wrapped in `Zeroizing<_>` to zero on drop

### TLS and HTTP Clients
- [ ] No `danger_accept_invalid_certs(true)` or `danger_accept_invalid_hostnames(true)`
- [ ] `rustls` preferred over `native-tls` for new projects
- [ ] Timeouts set on all HTTP clients

### SSRF
- [ ] User-supplied URLs validated for scheme, host, and resolved IP
- [ ] Private/loopback/link-local IPs blocked
- [ ] Redirects limited or disabled for user-supplied URLs

### Panic Safety
- [ ] No `.unwrap()` in request-handling code paths
- [ ] Array/slice access uses `.get()` for untrusted indices
- [ ] Tokio tasks handle `JoinError` (panic propagation)

### Web Frameworks
- [ ] Request body size limits configured
- [ ] CORS allows only specific origins (no permissive mode in production)
- [ ] Session cookies have `SameSite=Strict`, `HttpOnly`, `Secure`
- [ ] Security headers added via middleware layer

### Logging
- [ ] No passwords, tokens, or PII logged
- [ ] Sensitive struct fields use `secrecy::Secret<T>`
- [ ] `tracing::instrument` uses `skip()` for sensitive parameters

### Supply Chain
- [ ] `cargo audit` runs in CI and fails the build on vulnerabilities
- [ ] `Cargo.lock` committed for application crates
- [ ] `cargo-deny` configured with allowed licenses and banned crates
- [ ] Security-critical crates pinned with `=` or `~` version specifiers

---

## Tooling

| Tool | Purpose | Command |
|------|---------|---------|
| [cargo-audit](https://github.com/rustsec/rustsec/tree/main/cargo-audit) | Checks `Cargo.lock` against the RustSec advisory database | `cargo audit` |
| [cargo-deny](https://github.com/EmbarkStudios/cargo-deny) | License compliance, banned crates, advisory enforcement | `cargo deny check` |
| [cargo-geiger](https://github.com/geiger-rs/cargo-geiger) | Counts `unsafe` usage in crate and all dependencies | `cargo geiger` |
| [cargo-vet](https://github.com/mozilla/cargo-vet) | Supply-chain auditing — tracks which crates have been reviewed | `cargo vet` |
| [clippy](https://github.com/rust-lang/rust-clippy) | Linter with security-relevant lints (`clippy::all`, `clippy::pedantic`) | `cargo clippy -- -D warnings` |
| [rustsec/advisories](https://rustsec.org/advisories/) | RustSec advisory database — browse Rust CVEs and RUSTSEC advisories | — |
| [cargo-fuzz](https://github.com/rust-fuzz/cargo-fuzz) | LibFuzzer-based fuzzing for finding panics and memory issues | `cargo fuzz run fuzz_target_1` |
| [semgrep (Rust rules)](https://semgrep.dev/r?lang=rust) | Static analysis patterns for Rust security anti-patterns | `semgrep --config=r/rust.lang.security .` |
