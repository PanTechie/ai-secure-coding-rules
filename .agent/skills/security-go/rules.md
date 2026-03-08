# 🐹 Go Security Rules

> **Standard:** Security rules for Go 1.21+ applications including web services, microservices, CLIs, and cloud-native workloads.
> **Sources:** Go Security Policy, OWASP Top 10:2025, CWE/MITRE, NVD/CVE Database, GitHub Advisory Database, Go Vulnerability Database (pkg.go.dev/vuln), CNCF Security Whitepaper, Google Project Zero
> **Version:** 1.0.0
> **Last updated:** March 2026
> **Scope:** Go 1.21+ standard library and common frameworks (net/http, gin, echo, chi, gorilla/mux, gRPC, database/sql, GORM, sqlx, os/exec, crypto/*, encoding/json, encoding/xml, archive/zip, path/filepath). CGo memory safety is covered by code-security-c-cpp.md.

---

## General Instructions

Apply these rules when writing or reviewing Go code. Go's memory safety, garbage collection, and strong typing eliminate C/C++ vulnerability classes — but Go has its own distinct risk profile: **goroutine data races on shared maps/slices** are silent undefined behavior causing random crashes, data corruption, or security bypasses; **`os/exec` with shell invocation enables command injection**; **`database/sql` with `fmt.Sprintf` enables SQL injection** (raw queries are common in Go); **`text/template` has no auto-escaping** (unlike `html/template`); and **`net/http` servers have no default timeouts**, making them trivially DoS-able. Go modules and the Go checksum database provide strong supply-chain guarantees — but only when `go.sum` is committed and `govulncheck` runs in CI.

---

## 1. Command Injection via `os/exec`

**Vulnerability:** `exec.Command("sh", "-c", userInput)` passes input to a shell interpreter; metacharacters (`;`, `|`, `$()`, backticks) execute additional commands. `exec.Command(userInput)` lets an attacker choose the binary name entirely. Shell expansion happens before the child process receives arguments, so no amount of quoting inside the string prevents injection.

**References:** CWE-78

### Mandatory Rules

- **Never use shell forms** — `exec.Command("sh", "-c", ...)` and `exec.Command("bash", "-c", ...)` pass the entire argument string through a shell, enabling metacharacter injection.
- **Pass arguments as separate elements to `exec.Command`** — the OS passes them directly to `execve`, bypassing shell interpretation entirely.
- **Never include user input in the command name (first argument)** — the first argument controls which binary is executed; an attacker could supply `/bin/sh` or any accessible binary.
- **Validate and allowlist any argument that comes from user input** before passing it to `exec.Command`; reject arguments containing shell metacharacters even when not using a shell form, as defense in depth.
- **Use `exec.CommandContext`** so the command is killed when the request context is cancelled, preventing resource leaks from long-running child processes.

```go
// ❌ INSECURE — shell interprets metacharacters; userInput = "foo; rm -rf /"
cmd := exec.Command("sh", "-c", "grep "+userInput+" /var/log/app.log")
out, err := cmd.Output()

// ❌ INSECURE — user controls binary name; attacker passes "/bin/sh"
cmd := exec.Command(userSuppliedBinary, args...)

// ✅ SECURE — argument array; OS passes directly to execve, no shell interpretation
cmd := exec.CommandContext(ctx, "grep", "--", userInput, "/var/log/app.log")
out, err := cmd.Output()
if err != nil {
    return fmt.Errorf("grep failed: %w", err)
}
```

---

## 2. SQL Injection via `database/sql`, GORM, sqlx

**Vulnerability:** String interpolation or concatenation in SQL queries allows an attacker to alter query structure, bypass authentication, exfiltrate data, or execute admin commands. Raw queries with `fmt.Sprintf` are common in Go codebases because the ORM abstraction is thin — developers frequently drop to raw SQL for performance or complex queries, introducing this risk.

**References:** CWE-89, CVE-2020-26160

### Mandatory Rules

- **Always use parameterized queries** with `?` (MySQL/SQLite) or `$1` (PostgreSQL) placeholders — the database driver handles quoting and escaping.
- **Never use `fmt.Sprintf`, `+`, or `strings.Builder`** to construct SQL strings with user-supplied values under any circumstances.
- **In GORM:** use the `?` placeholder in `Where`, `Raw`, and `Exec` calls; never pass a raw string containing user data as the first argument to these methods.
- **In sqlx:** use `sqlx.NamedExec` / `db.NamedQuery` with struct binding or `:name` placeholders to avoid positional confusion with many parameters.
- **Allowlist column names and ORDER BY directions** when they come from user input — column names and SQL keywords cannot be parameterized and must be validated against a hardcoded set.

```go
// ❌ INSECURE — SQL injection via fmt.Sprintf
row := db.QueryRow(fmt.Sprintf("SELECT * FROM users WHERE email = '%s'", email))

// ❌ INSECURE — GORM raw string with user data
db.Where(fmt.Sprintf("name = '%s'", name)).Find(&users)

// ❌ INSECURE — dynamic column name without validation
db.Order(r.FormValue("sort") + " " + r.FormValue("dir")).Find(&users)

// ✅ SECURE — parameterized query with $1 placeholder (PostgreSQL)
row := db.QueryRowContext(ctx, "SELECT id, name FROM users WHERE email = $1", email)

// ✅ SECURE — GORM with ? placeholder
db.Where("name = ?", name).Find(&users)

// ✅ SECURE — ORDER BY with strict allowlist for column and direction
allowedCols := map[string]bool{"name": true, "created_at": true, "email": true}
allowedDirs := map[string]bool{"asc": true, "desc": true}
orderBy := r.FormValue("sort")
direction := strings.ToLower(r.FormValue("dir"))
if !allowedCols[orderBy] {
    orderBy = "created_at"
}
if !allowedDirs[direction] {
    direction = "asc"
}
db.Order(orderBy + " " + direction).Find(&users)

// ✅ SECURE — sqlx named query
type UserFilter struct {
    Email string `db:"email"`
}
rows, err := sqlx.NamedQueryContext(ctx, db,
    "SELECT id, name FROM users WHERE email = :email", UserFilter{Email: email})
```

---

## 3. Path Traversal via `path/filepath` and File Operations

**Vulnerability:** `filepath.Join(base, userInput)` cleans `../` sequences but the result can still escape the base directory if the base itself does not end with a path separator, or if the resolved path follows symlinks that point outside the base. An attacker supplying `../../../../etc/passwd` or a symlink-based payload can read arbitrary files.

**References:** CWE-22, CVE-2023-29197

### Mandatory Rules

- **After joining, call `filepath.EvalSymlinks`** to resolve all symlinks, then verify the resolved path has `base + string(os.PathSeparator)` as a prefix — this is the only reliable traversal check.
- **Use `http.Dir` with `http.FileServer`** for safe static file serving — it handles traversal and symlink checks internally; do not reimplement this logic.
- **Never use `os.Open(r.URL.Path)` directly** — the URL path is attacker-controlled and `path.Clean` alone is insufficient protection.
- **Validate uploaded filenames** with `filepath.Base` to strip directory components; reject filenames containing `/`, `\`, or `..`.
- **Use `os.OpenFile` with `os.O_EXCL`** for new file creation to prevent TOCTOU races between check and open.

```go
// ❌ INSECURE — ../../../etc/passwd bypasses base check on some configurations
p := filepath.Join(baseDir, r.URL.Query().Get("file"))
data, err := os.ReadFile(p)

// ❌ INSECURE — URL path used directly with Open
f, err := os.Open(r.URL.Path)

// ✅ SECURE — resolve symlinks, then prefix-check against base with separator
func safeReadFile(baseDir, userPath string) ([]byte, error) {
    joined := filepath.Join(baseDir, userPath)
    resolved, err := filepath.EvalSymlinks(joined)
    if err != nil {
        return nil, fmt.Errorf("invalid path: %w", err)
    }
    prefix := baseDir + string(os.PathSeparator)
    if !strings.HasPrefix(resolved, prefix) {
        return nil, errors.New("path traversal detected")
    }
    return os.ReadFile(resolved)
}

// ✅ SECURE — safe filename from upload
filename := filepath.Base(header.Filename)
if filename == "." || filename == "/" || strings.ContainsAny(filename, `\/`) {
    http.Error(w, "invalid filename", http.StatusBadRequest)
    return
}
destPath := filepath.Join(uploadDir, uuid.New().String())
```

---

## 4. Goroutine Data Races on Maps and Slices

**Vulnerability:** Go maps are not safe for concurrent read/write or concurrent write/write access. The Go specification explicitly states that concurrent access to a map without synchronization is undefined behavior — it causes random panics, silent data corruption, stale reads, and in security-sensitive code (e.g., session stores, rate limiters, cache layers) can result in authorization bypasses or privilege escalation.

**References:** CWE-362

### Mandatory Rules

- **Never read or write a `map` from multiple goroutines without synchronization** — every concurrent read + write combination is a data race even if only one goroutine writes.
- **Use `sync.RWMutex` wrapping the map** for straightforward caches and stores; use `sync.Map` for high-contention scenarios where keys are written once and read many times.
- **Run `go test -race ./...` in CI** — the race detector instruments memory accesses at runtime and reliably finds data races that code review misses.
- **Prefer channel ownership transfer** over shared pointers when possible — a goroutine that owns exclusive access to a value needs no lock.
- **Slices are not safe for concurrent append** — appending may reallocate the backing array; protect slice mutation with a mutex or use a buffered channel as a work queue.

```go
// ❌ INSECURE — concurrent map write: data race, runtime panic, potential auth bypass
var cache = map[string]Session{}
go func() { cache[token] = session }() // data race — no synchronization

// ❌ INSECURE — concurrent map read+write without lock
func getSession(token string) Session { return cache[token] } // races with writes

// ✅ SECURE — sync.RWMutex wrapper pattern
type SessionStore struct {
    mu    sync.RWMutex
    store map[string]Session
}

func NewSessionStore() *SessionStore {
    return &SessionStore{store: make(map[string]Session)}
}

func (s *SessionStore) Set(token string, sess Session) {
    s.mu.Lock()
    defer s.mu.Unlock()
    s.store[token] = sess
}

func (s *SessionStore) Get(token string) (Session, bool) {
    s.mu.RLock()
    defer s.mu.RUnlock()
    sess, ok := s.store[token]
    return sess, ok
}

func (s *SessionStore) Delete(token string) {
    s.mu.Lock()
    defer s.mu.Unlock()
    delete(s.store, token)
}
```

---

## 5. Missing HTTP Server Timeouts (DoS)

**Vulnerability:** `http.ListenAndServe` with no configured `http.Server` struct uses zero-value timeouts — meaning connections are kept alive indefinitely. A slow client that trickles headers (Slowloris) or never reads a response keeps a goroutine and file descriptor open forever, exhausting the server. Go 1.21 introduced `http.Server.ReadHeaderTimeout` but still applies no defaults.

**References:** CWE-400, CVE-2023-44487 (HTTP/2 Rapid Reset)

### Mandatory Rules

- **Always configure `ReadTimeout`, `WriteTimeout`, `IdleTimeout`, and `ReadHeaderTimeout`** on every `http.Server` — never use the convenience function `http.ListenAndServe` in production.
- **Set `http.Client.Timeout`** on all outbound HTTP clients — the default is no timeout, causing goroutine and connection leaks on slow or unresponsive upstream services.
- **For HTTP/2, configure `http2.Server{MaxConcurrentStreams: N}`** to bound the impact of Rapid Reset (CVE-2023-44487) stream exhaustion attacks.
- **Use `http.MaxBytesReader(w, r.Body, maxBytes)`** to limit request body size before reading — without this, a client sending a multi-gigabyte body causes memory exhaustion.
- **Set `MaxHeaderBytes`** on the server struct (default is 1 MB, which is usually acceptable, but should be explicit).

```go
// ❌ INSECURE — no timeouts; vulnerable to Slowloris, goroutine leak, connection exhaustion
http.ListenAndServe(":8080", mux)

// ❌ INSECURE — outbound client with no timeout; goroutine leaks on slow upstream
resp, err := http.Get(externalURL)

// ✅ SECURE — explicit timeouts on server
srv := &http.Server{
    Addr:              ":8443",
    Handler:           mux,
    ReadTimeout:       5 * time.Second,
    ReadHeaderTimeout: 2 * time.Second,
    WriteTimeout:      10 * time.Second,
    IdleTimeout:       120 * time.Second,
    MaxHeaderBytes:    1 << 20, // 1 MB
}
log.Fatal(srv.ListenAndServeTLS("cert.pem", "key.pem"))

// ✅ SECURE — outbound client with timeout
client := &http.Client{Timeout: 10 * time.Second}

// ✅ SECURE — limit request body size in handler
func uploadHandler(w http.ResponseWriter, r *http.Request) {
    r.Body = http.MaxBytesReader(w, r.Body, 10<<20) // 10 MB
    if err := r.ParseMultipartForm(10 << 20); err != nil {
        http.Error(w, "request too large", http.StatusRequestEntityTooLarge)
        return
    }
}
```

---

## 6. Cryptography Misuse

**Vulnerability:** `math/rand` is a deterministic PRNG — in Go versions before 1.20 it defaults to a fixed seed of 1; in Go 1.20+ it auto-seeds but is still not cryptographically secure and must not be used for tokens, session IDs, or nonces. `crypto/md5` and `crypto/sha1` are broken for security purposes. AES-CBC without a MAC is malleable — an attacker can flip ciphertext bits to alter plaintext predictably.

**References:** CWE-327, CWE-338, CWE-916

### Mandatory Rules

- **Use `crypto/rand.Read` for all security-sensitive random bytes** — never `math/rand` for tokens, session IDs, CSRF tokens, nonces, or salts.
- **Hash passwords with `golang.org/x/crypto/bcrypt` (cost ≥ 12) or `golang.org/x/crypto/argon2`** — never hash passwords with SHA-256, SHA-512, or MD5 alone.
- **Use AES-256-GCM (`cipher.NewGCM`)** for symmetric encryption — GCM provides both confidentiality and authenticity; never use AES-ECB (no IV, identical blocks produce identical ciphertext) or AES-CBC without a separate HMAC.
- **Generate a fresh random 12-byte nonce per GCM encryption** with `crypto/rand.Read` — GCM nonce reuse with the same key is catastrophic, enabling key recovery.
- **RSA keys must be at least 2048 bits**; prefer ECDSA P-256 or Ed25519 for new code — smaller and faster with equivalent or superior security.
- **Never hardcode keys, IVs, or salts** in source code — load from environment variables or a secrets manager.

```go
// ❌ INSECURE — math/rand for security token; predictable
import "math/rand"
token := fmt.Sprintf("%d", rand.Int63())

// ❌ INSECURE — MD5 for password storage; broken and fast (brute-forceable)
h := md5.Sum([]byte(password))
storedHash = hex.EncodeToString(h[:])

// ❌ INSECURE — AES-CBC without authentication; malleable ciphertext
block, _ := aes.NewCipher(key)
mode := cipher.NewCBCEncrypter(block, iv)
mode.CryptBlocks(ciphertext, plaintext)

// ✅ SECURE — crypto/rand for unpredictable token
import crypto_rand "crypto/rand"
b := make([]byte, 32)
if _, err := crypto_rand.Read(b); err != nil {
    return fmt.Errorf("rand read: %w", err)
}
token := base64.URLEncoding.EncodeToString(b)

// ✅ SECURE — bcrypt password hashing (cost 12 recommended for 2026 hardware)
import "golang.org/x/crypto/bcrypt"
hash, err := bcrypt.GenerateFromPassword([]byte(password), 12)
if err != nil { return fmt.Errorf("bcrypt: %w", err) }

// ✅ SECURE — AES-256-GCM with random nonce
func encrypt(key, plaintext []byte) ([]byte, error) {
    block, err := aes.NewCipher(key) // key must be exactly 32 bytes for AES-256
    if err != nil { return nil, err }
    gcm, err := cipher.NewGCM(block)
    if err != nil { return nil, err }
    nonce := make([]byte, gcm.NonceSize())
    if _, err = crypto_rand.Read(nonce); err != nil { return nil, err }
    return gcm.Seal(nonce, nonce, plaintext, nil), nil // nonce prepended to ciphertext
}
```

---

## 7. XSS via `text/template` Instead of `html/template`

**Vulnerability:** `text/template` outputs all values verbatim — no HTML escaping is performed. Any user-controlled value rendered through `text/template` in an HTTP response is an XSS vector. Even when using `html/template`, explicitly casting to `template.HTML`, `template.JS`, or `template.URL` bypasses the auto-escaping mechanism and reintroduces the vulnerability.

**References:** CWE-79, CVE-2023-24540, CVE-2023-29400

### Mandatory Rules

- **Always import and use `html/template` for HTML output** — never `text/template`; the package names are identical so check imports carefully.
- **Never cast user input to `template.HTML`, `template.JS`, `template.URL`, or `template.CSS`** — these types signal to the template engine that the value is pre-sanitized; user input is not.
- **Avoid `fmt.Fprintf(w, "<h1>%s</h1>", userInput)`** — use templates with proper context-aware escaping instead of manually building HTML strings.
- **Set the `Content-Type: text/html; charset=utf-8` response header** explicitly — without `charset=utf-8`, some browsers use content sniffing and may be tricked into interpreting the response as a different encoding.
- **Use `html.EscapeString`** when building HTML strings outside of templates (e.g., in helper functions) as a last resort — templates are strongly preferred.

```go
// ❌ INSECURE — text/template: no escaping; <script>alert(1)</script> executes in browser
import "text/template"
tmpl := template.Must(template.New("page").Parse(`<h1>Hello {{.Name}}</h1>`))
tmpl.Execute(w, map[string]string{"Name": userName})

// ❌ INSECURE — explicit bypass of html/template auto-escaping
import "html/template"
tmpl.Execute(w, map[string]interface{}{
    "Bio": template.HTML(userBio), // user controls raw HTML
})

// ❌ INSECURE — manual HTML construction with fmt
fmt.Fprintf(w, "<title>%s</title>", r.FormValue("title"))

// ✅ SECURE — html/template with auto-escaping (context-aware: HTML, JS, URL, CSS)
import "html/template"
var tmpl = template.Must(template.New("page").Parse(`
<!DOCTYPE html>
<html><head><title>{{.Title}}</title></head>
<body><h1>Hello, {{.Name}}</h1></body></html>
`))

func handler(w http.ResponseWriter, r *http.Request) {
    w.Header().Set("Content-Type", "text/html; charset=utf-8")
    tmpl.Execute(w, map[string]string{
        "Title": r.FormValue("title"), // automatically HTML-escaped
        "Name":  r.FormValue("name"),  // automatically HTML-escaped
    })
}
```

---

## 8. SSRF via `http.Get` and `net.Dial`

**Vulnerability:** Fetching a user-supplied URL allows access to internal services not reachable from the public internet — the AWS instance metadata service (169.254.169.254), internal databases, the Kubernetes API server at 10.0.0.1:443, Redis on localhost, or other cloud provider metadata endpoints. DNS rebinding can bypass hostname-based checks by returning a public IP during resolution then a private IP during the actual connection.

**References:** CWE-918

### Mandatory Rules

- **Parse the URL and validate the scheme is `https`** — block `http`, `file`, `ftp`, `gopher`, and custom schemes.
- **Validate the hostname against an allowlist** of permitted external services before making any network call.
- **Resolve the hostname to IP addresses and check each IP** against private/loopback/link-local ranges using `net.IP.IsPrivate()`, `net.IP.IsLoopback()`, and manual checks for 169.254.0.0/16 — this prevents DNS rebinding.
- **Disable HTTP redirect following or validate redirect targets** with a custom `CheckRedirect` function using the same allowlist; by default `http.Client` follows up to 10 redirects unconditionally.
- **Never pass `r.URL.Query().Get("url")` or any user-controlled value directly to `http.Get`**.

```go
// ❌ INSECURE — fetches arbitrary URL including 169.254.169.254 (AWS IMDS)
targetURL := r.URL.Query().Get("url")
resp, err := http.Get(targetURL)

// ✅ SECURE — validate scheme, allowlist host, block private IPs, check DNS result
var allowedHosts = map[string]bool{
    "api.example.com":  true,
    "data.example.com": true,
}

func safeGet(ctx context.Context, rawURL string) (*http.Response, error) {
    u, err := url.Parse(rawURL)
    if err != nil || u.Scheme != "https" {
        return nil, errors.New("invalid URL or scheme")
    }
    host := u.Hostname()
    if !allowedHosts[host] {
        return nil, errors.New("host not in allowlist")
    }
    addrs, err := net.DefaultResolver.LookupHost(ctx, host)
    if err != nil {
        return nil, fmt.Errorf("DNS lookup: %w", err)
    }
    for _, addr := range addrs {
        ip := net.ParseIP(addr)
        if ip == nil || ip.IsPrivate() || ip.IsLoopback() || ip.IsLinkLocalUnicast() {
            return nil, fmt.Errorf("resolved IP %s is private/loopback", addr)
        }
        // Block cloud metadata endpoints explicitly
        if strings.HasPrefix(addr, "169.254.") || strings.HasPrefix(addr, "100.64.") {
            return nil, errors.New("cloud metadata IP blocked")
        }
    }
    client := &http.Client{
        Timeout: 10 * time.Second,
        CheckRedirect: func(req *http.Request, via []*http.Request) error {
            if !allowedHosts[req.URL.Hostname()] {
                return errors.New("redirect to non-allowlisted host")
            }
            return nil
        },
    }
    req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
    if err != nil { return nil, err }
    return client.Do(req)
}
```

---

## 9. Insecure TLS Configuration

**Vulnerability:** `InsecureSkipVerify: true` disables all certificate validation — any server presenting any certificate (including self-signed or attacker-controlled) is accepted, enabling trivial man-in-the-middle attacks. `MinVersion: tls.VersionTLS10` allows downgrade to broken protocol versions. These options are frequently introduced during development and committed to production.

**References:** CWE-295, CVE-2022-27664

### Mandatory Rules

- **Never set `InsecureSkipVerify: true` in production** — not even for internal services; use a corporate CA pool (`tls.Config.RootCAs`) instead.
- **Set `MinVersion: tls.VersionTLS12` at minimum**; prefer `tls.VersionTLS13` for new services where client compatibility is not a concern.
- **Load a custom `RootCAs` pool for internal services** to pin trust to the internal CA rather than the system root store.
- **Do not set `InsecureSkipVerify` via environment variable injection** — treat it as equivalent to hardcoding it.
- **For mutual TLS (gRPC, service mesh):** configure `ClientCAs` with the expected client CA and set `ClientAuth: tls.RequireAndVerifyClientCert` to authenticate callers.
- **Avoid manually specifying deprecated cipher suites** — do not configure `CipherSuites` for TLS 1.3 (it ignores them anyway); for TLS 1.2, omit non-forward-secret suites.

```go
// ❌ INSECURE — disables all certificate validation; trivial MitM
tr := &http.Transport{
    TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
}
client := &http.Client{Transport: tr}

// ❌ INSECURE — allows deprecated TLS 1.0 and 1.1
cfg := &tls.Config{MinVersion: tls.VersionTLS10}

// ✅ SECURE — strict TLS with minimum version and forward-secret curves
cfg := &tls.Config{
    MinVersion: tls.VersionTLS12,
    CurvePreferences: []tls.CurveID{
        tls.X25519, tls.CurveP256,
    },
    PreferServerCipherSuites: true,
}
tr := &http.Transport{
    TLSClientConfig:     cfg,
    DisableKeepAlives:   false,
    MaxIdleConnsPerHost: 10,
}
client := &http.Client{Transport: tr, Timeout: 10 * time.Second}

// ✅ SECURE — internal CA pinning for service-to-service calls
certPool := x509.NewCertPool()
caCert, err := os.ReadFile("/etc/ssl/internal-ca.pem")
if err != nil { log.Fatal(err) }
certPool.AppendCertsFromPEM(caCert)
cfg := &tls.Config{
    RootCAs:    certPool,
    MinVersion: tls.VersionTLS12,
}
```

---

## 10. JWT Vulnerabilities (`golang-jwt`, `go-jose`)

**Vulnerability:** CVE-2020-26160 — the widely-used `dgrijalva/jwt-go` library (now unmaintained) contained logic that allowed the `alg: none` bypass, where an attacker submits a token with no signature and the library accepted it if the key function returned `nil` without error. Key functions that do not validate the signing method type are vulnerable to algorithm confusion attacks (e.g., RS256 to HS256 downgrade using the public key as the HMAC secret).

**References:** CWE-347, CVE-2020-26160

### Mandatory Rules

- **Migrate from `dgrijalva/jwt-go` to `github.com/golang-jwt/jwt/v5`** — the original package is unmaintained and CVE-affected.
- **Always check `token.Method` type against the expected signing method** in the key function before returning the key — reject unexpected algorithms.
- **Validate `exp`, `iss`, and `aud` claims explicitly** using the library's built-in validation options — do not assume claims are valid if `Parse` returns no error.
- **Use RS256 or ES256 for tokens issued to external clients** — HMAC (HS256) requires the verifier to know the secret, which clients should not have.
- **Load signing secrets from environment variables or a secrets manager** — never hardcode them in source.
- **Set `jwt.WithExpirationRequired()`** to reject tokens without an `exp` claim.

```go
// ❌ INSECURE — no algorithm check; accepts any alg including "none"
import "github.com/golang-jwt/jwt/v5"
token, err := jwt.Parse(tokenStr, func(t *jwt.Token) (interface{}, error) {
    return []byte(secret), nil // blindly returns key regardless of alg
})

// ❌ INSECURE — unmaintained package with CVE-2020-26160
import jwtv3 "github.com/dgrijalva/jwt-go"

// ✅ SECURE — explicit HMAC algorithm check + claim validation
import "github.com/golang-jwt/jwt/v5"

var jwtSecret = []byte(os.Getenv("JWT_SECRET"))

func parseToken(tokenStr string) (jwt.MapClaims, error) {
    token, err := jwt.Parse(tokenStr,
        func(t *jwt.Token) (interface{}, error) {
            if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
                return nil, fmt.Errorf("unexpected signing method: %v", t.Header["alg"])
            }
            return jwtSecret, nil
        },
        jwt.WithExpirationRequired(),
        jwt.WithIssuer("https://auth.myapp.com"),
        jwt.WithAudience("https://api.myapp.com"),
    )
    if err != nil || !token.Valid {
        return nil, fmt.Errorf("invalid token: %w", err)
    }
    return token.Claims.(jwt.MapClaims), nil
}
```

---

## 11. XML Processing and XXE

**Vulnerability:** Go's `encoding/xml` package does not resolve external entities by default, making it safe against classic XXE. However, third-party XML libraries (`github.com/beevik/etree`, `libxml2` via CGo) may not have the same safety, and billion-laughs entity expansion (a form of DoS using recursive entity references within the document itself) is still possible without input size limits.

**References:** CWE-611, CWE-776

### Mandatory Rules

- **Always wrap XML input with `http.MaxBytesReader`** before decoding to prevent billion-laughs DoS — a deeply nested entity bomb can expand to gigabytes from a small input.
- **Verify external entity resolution is disabled** in any third-party XML library; for CGo-based parsers (libxml2), call `xmlSetExternalEntityLoader(NULL)` explicitly.
- **Avoid `xml.Unmarshal` on untrusted data** without an explicit size limit applied first — prefer `xml.NewDecoder(limitedReader)`.
- **Set a maximum nesting depth limit** when processing XML with recursive structures to prevent stack exhaustion via deeply nested elements.
- **Reject XML documents referencing external DTDs** — inspect the DOCTYPE declaration before processing if using a library that supports DTDs.

```go
// ❌ INSECURE — no size limit; billion-laughs or deeply nested document causes DoS
var result MyStruct
if err := xml.NewDecoder(r.Body).Decode(&result); err != nil {
    http.Error(w, "bad XML", http.StatusBadRequest)
}

// ❌ INSECURE — xml.Unmarshal without size protection
body, _ := io.ReadAll(r.Body) // reads unlimited bytes
xml.Unmarshal(body, &result)

// ✅ SECURE — limit input size before decoding
func xmlHandler(w http.ResponseWriter, r *http.Request) {
    const maxBodySize = 1 << 20 // 1 MB
    r.Body = http.MaxBytesReader(w, r.Body, maxBodySize)

    var result MyStruct
    dec := xml.NewDecoder(r.Body)
    if err := dec.Decode(&result); err != nil {
        if strings.Contains(err.Error(), "http: request body too large") {
            http.Error(w, "request body too large", http.StatusRequestEntityTooLarge)
        } else {
            http.Error(w, "invalid XML", http.StatusBadRequest)
        }
        return
    }
    // process result
}
```

---

## 12. JSON Deserialization — Type Confusion and Integer Truncation

**Vulnerability:** `json.Unmarshal` into `interface{}` decodes all JSON numbers as `float64`, silently truncating integers larger than 2^53 — an attacker can supply a 64-bit user ID that maps to a different user after truncation. `json.Decoder` without `DisallowUnknownFields()` silently ignores extra fields, allowing parameter injection or mass-assignment vulnerabilities.

**References:** CWE-704, CWE-190

### Mandatory Rules

- **Use `json.Decoder.DisallowUnknownFields()`** for all API request handlers — this prevents unexpected field injection and makes the API contract explicit.
- **Use typed structs (not `interface{}` or `map[string]interface{}`)** for JSON that includes IDs or counts — struct fields with `int64` or `json.Number` preserve precision.
- **Limit request body size with `http.MaxBytesReader`** before decoding — without this, a client can send an arbitrarily large JSON body causing memory exhaustion.
- **Validate all decoded values** after unmarshaling — JSON types are coarse (number, string, boolean, array, object); business constraints (ranges, formats, lengths) require explicit validation.
- **Use `json.Number` for large integers** when decoding into `interface{}` is unavoidable — call `json.Decoder.UseNumber()` to preserve precision.

```go
// ❌ INSECURE — unknown fields accepted silently; large IDs truncated by float64
var payload map[string]interface{}
json.NewDecoder(r.Body).Decode(&payload)
id := int64(payload["user_id"].(float64)) // silently wrong for id > 2^53

// ❌ INSECURE — no body size limit
json.NewDecoder(r.Body).Decode(&req) // attacker sends 10 GB JSON

// ✅ SECURE — typed struct, strict field validation, size limit
type CreateOrderRequest struct {
    ProductID int64  `json:"product_id"`
    Quantity  int    `json:"quantity"`
    Notes     string `json:"notes"`
}

func createOrderHandler(w http.ResponseWriter, r *http.Request) {
    r.Body = http.MaxBytesReader(w, r.Body, 64*1024) // 64 KB limit
    dec := json.NewDecoder(r.Body)
    dec.DisallowUnknownFields()

    var req CreateOrderRequest
    if err := dec.Decode(&req); err != nil {
        http.Error(w, "bad request", http.StatusBadRequest)
        return
    }
    // Explicit validation after decoding
    if req.ProductID <= 0 || req.Quantity < 1 || req.Quantity > 1000 {
        http.Error(w, "invalid parameters", http.StatusBadRequest)
        return
    }
    if len(req.Notes) > 500 {
        http.Error(w, "notes too long", http.StatusBadRequest)
        return
    }
}
```

---

## 13. Open Redirect

**Vulnerability:** `http.Redirect(w, r, r.FormValue("next"), 302)` redirects to any URL supplied by an attacker. This enables phishing (redirect to a lookalike login page after a real login), credential harvesting, and OAuth token theft when combined with authorization flows that use the redirect URI.

**References:** CWE-601

### Mandatory Rules

- **Never redirect to a URL taken directly from user input** without validation.
- **For post-login redirects, validate the URL is a relative path** starting with `/` and not `//` — a `//evil.com` URL is treated as a protocol-relative absolute URL by browsers.
- **Reject paths with a scheme component** — after calling `url.Parse`, check `u.IsAbs()` returns false.
- **Allowlist destination hosts** if absolute URLs are a product requirement — derive the allowed host from configuration, not request parameters.
- **Do not trust the `Referer` header** for redirect validation — it is attacker-controlled.

```go
// ❌ INSECURE — attacker supplies "https://evil.com" → user redirected to phishing site
next := r.FormValue("next")
http.Redirect(w, r, next, http.StatusFound)

// ❌ INSECURE — "//evil.com" starts with "/" but is not a relative path
if strings.HasPrefix(next, "/") {
    http.Redirect(w, r, next, http.StatusFound)
}

// ✅ SECURE — parse and validate: relative path only, no scheme, no authority
func safeRedirect(w http.ResponseWriter, r *http.Request, fallback string) {
    next := r.FormValue("next")
    u, err := url.Parse(next)
    if err != nil || u.IsAbs() || u.Host != "" ||
        !strings.HasPrefix(u.Path, "/") || strings.HasPrefix(u.Path, "//") {
        next = fallback
    } else {
        // Prevent path traversal via double-dot segments in redirect
        cleaned := path.Clean(u.Path)
        if !strings.HasPrefix(cleaned, "/") {
            next = fallback
        } else {
            next = cleaned
        }
    }
    http.Redirect(w, r, next, http.StatusFound)
}
```

---

## 14. HTTP Response Header Injection (CRLF)

**Vulnerability:** Setting a response header with a user-supplied value containing `\r\n` (carriage return + line feed) allows an attacker to inject additional headers or split the HTTP response into two responses, bypassing security headers and potentially serving attacker-controlled content. Go's `net/http` panics on `\n` in header values since Go 1.6 but `\r` alone may not be caught consistently in all versions.

**References:** CWE-113

### Mandatory Rules

- **Sanitize header values before setting them** — strip or reject any value containing `\r`, `\n`, or null bytes (`\x00`).
- **Validate `Location` header values** using the same allowlist as redirect targets — `http.Redirect` calls `w.Header().Set("Location", url)` internally.
- **Use `http.Header.Set` rather than writing raw bytes** to the response writer for headers — the standard library provides some protection but is not a substitute for input validation.
- **Apply the same sanitization to headers derived from request headers** (e.g., correlation IDs, trace IDs, session identifiers copied from request to response).

```go
// ❌ INSECURE — CRLF injection: userValue = "ok\r\nSet-Cookie: admin=true"
// This injects a Set-Cookie header into the response
w.Header().Set("X-Request-ID", r.Header.Get("X-Request-ID"))

// ❌ INSECURE — reflected header value without sanitization
w.Header().Set("X-Trace-ID", r.FormValue("trace_id"))

// ✅ SECURE — strip control characters before setting header
func sanitizeHeaderValue(v string) string {
    return strings.Map(func(r rune) rune {
        if r == '\r' || r == '\n' || r == 0x00 {
            return -1 // drop the character
        }
        return r
    }, v)
}

func handler(w http.ResponseWriter, r *http.Request) {
    requestID := sanitizeHeaderValue(r.Header.Get("X-Request-ID"))
    if requestID == "" {
        requestID = uuid.New().String()
    }
    w.Header().Set("X-Request-ID", requestID)
    // rest of handler
}
```

---

## 15. Goroutine and Resource Leaks

**Vulnerability:** Goroutines that block on channels or network I/O without a cancellation mechanism run indefinitely. `context.WithCancel` or `context.WithTimeout` that never call `cancel()` leak an internal timer goroutine. `http.Client` used without a request context in long-running services leaks goroutines when upstream services are slow. Over time, leaked goroutines consume memory, sockets, and file descriptors, eventually causing OOM crashes.

**References:** CWE-400, CWE-772

### Mandatory Rules

- **Always pass `context.Context` as the first argument** to functions that perform I/O or spawn goroutines — this is the primary cancellation mechanism in Go.
- **Always `defer cancel()` immediately after `context.WithCancel` or `context.WithTimeout`** — without this, the goroutine managing the timer runs until the program exits.
- **Use `http.NewRequestWithContext`** (not `http.Get`) in services — `http.Get` does not accept a context and leaks goroutines on slow upstreams.
- **Close `resp.Body` with `defer resp.Body.Close()`** after every `http.Client.Do` call — not closing the body prevents connection reuse and leaks the underlying TCP connection.
- **Use `goleak` in tests** (`go.uber.org/goleak`) to detect goroutine leaks automatically before they reach production.

```go
// ❌ INSECURE — cancel never called; timer goroutine leaks
ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
// missing: defer cancel()
resp, err := http.Get(url) // doesn't use ctx, can't be cancelled

// ❌ INSECURE — response body never closed; connection not reused, descriptor leak
resp, err := client.Do(req)
if err != nil { return err }
data, err := io.ReadAll(resp.Body)

// ✅ SECURE — defer cancel immediately, use context-aware request, close body
func fetchData(ctx context.Context, client *http.Client, url string) ([]byte, error) {
    ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
    defer cancel() // always called, even on error paths

    req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
    if err != nil {
        return nil, fmt.Errorf("create request: %w", err)
    }
    resp, err := client.Do(req)
    if err != nil {
        return nil, fmt.Errorf("do request: %w", err)
    }
    defer resp.Body.Close() // always closed

    return io.ReadAll(io.LimitReader(resp.Body, 10<<20)) // 10 MB read limit
}
```

---

## 16. Sensitive Data in Logs

**Vulnerability:** Logging struct values with `%+v` or `%#v` in `fmt.Printf`/`log.Printf` exposes all exported fields, including passwords, tokens, and PII. Logging `r.Header` exposes the `Authorization` bearer token, `Cookie` session tokens, and API keys. In structured logging with `slog` (Go 1.21+), logging entire request objects or error values can inadvertently expose internal paths and credentials.

**References:** CWE-532

### Mandatory Rules

- **Implement `String() string` (for `fmt`) or `LogValue() slog.Value` (for `slog`)** on any struct containing sensitive fields — return a redacted representation.
- **Never log `r.Header` directly** — it contains `Authorization`, `Cookie`, `X-Api-Key`, and similar; log only an explicit allowlist of safe headers.
- **Never log request or response bodies in production** unless they have been processed through a PII redaction pipeline.
- **Filter sensitive query parameters** from logged URLs — replace values for `password`, `token`, `api_key`, `secret`, and similar keys with `[REDACTED]`.
- **Use correlation/request IDs** in log entries rather than embedding user identifiers inline; this allows log correlation without storing PII in logs.

```go
// ❌ INSECURE — prints Password field in plain text
type Credentials struct{ Username, Password string }
log.Printf("login attempt: %+v", creds)

// ❌ INSECURE — logs Authorization header and all cookies
slog.Info("incoming request", "headers", r.Header)

// ✅ SECURE — implement LogValue for automatic slog redaction
type Credentials struct{ Username, Password string }

func (c Credentials) LogValue() slog.Value {
    return slog.GroupValue(
        slog.String("username", c.Username),
        slog.String("password", "[REDACTED]"),
    )
}
slog.Info("login attempt", "creds", creds) // password never appears in output

// ✅ SECURE — safe header logging using an explicit allowlist
func safeHeaders(h http.Header) http.Header {
    safe := http.Header{}
    allowed := []string{"Content-Type", "X-Request-ID", "User-Agent", "Accept"}
    for _, key := range allowed {
        if v := h.Get(key); v != "" {
            safe.Set(key, v)
        }
    }
    return safe
}
slog.Info("request received",
    "method", r.Method,
    "path", r.URL.Path,
    "headers", safeHeaders(r.Header),
)
```

---

## 17. Integer Overflow in Allocation and Arithmetic

**Vulnerability:** `make([]byte, count*size)` where `count` and `size` are derived from user input — if both are large, their product overflows a 64-bit integer and wraps to a small positive value before the allocation, resulting in an undersized buffer. Subsequent writes past the buffer boundary corrupt adjacent memory. Additionally, casting `int64` to `int32` silently truncates values above 2^31-1.

**References:** CWE-190, CWE-680

### Mandatory Rules

- **Check for overflow before multiplying user-controlled values** used in allocations — validate each factor individually against a maximum before multiplying.
- **Use `math/bits.Mul64` for overflow-checked 64-bit multiplication** — it returns the high and low 64-bit words of the result; if the high word is non-zero, overflow occurred.
- **Set maximum bounds on all user-supplied sizes** before passing to `make()` — this is the simplest and most robust defence.
- **Validate range before integer casts** — `int32(largeInt64)` silently truncates; check `val <= math.MaxInt32` first.
- **Use `io.LimitReader`** to cap the number of bytes read from streams — prevents allocation bombs from streaming input.

```go
// ❌ INSECURE — overflow: count=1<<30, size=8 → product wraps → make([]byte, 0)
// subsequent writes past undersized buffer corrupt memory
count := int(r.FormValue("count"))
size := int(r.FormValue("size"))
buf := make([]byte, count*size)

// ❌ INSECURE — silent int64 → int32 truncation
var userID int64 = 3000000000 // > MaxInt32
id := int32(userID) // wraps to -1294967296 → wrong user accessed

// ✅ SECURE — explicit bounds checks before multiplication
const maxItems = 10_000
const maxItemSize = 4096

func allocateBuffer(count, size int) ([]byte, error) {
    if count < 0 || count > maxItems {
        return nil, fmt.Errorf("count %d out of range [0, %d]", count, maxItems)
    }
    if size < 0 || size > maxItemSize {
        return nil, fmt.Errorf("size %d out of range [0, %d]", size, maxItemSize)
    }
    // After bounds check, multiplication is safe (max 10000 * 4096 = 40 MB, fits in int64)
    return make([]byte, count*size), nil
}

// ✅ SECURE — overflow-checked multiplication with math/bits
import "math/bits"

func safeMul(a, b uint64) (uint64, error) {
    hi, lo := bits.Mul64(a, b)
    if hi != 0 {
        return 0, errors.New("integer overflow")
    }
    return lo, nil
}
```

---

## 18. Panic Recovery and Error Information Disclosure

**Vulnerability:** An unrecovered `panic` in an HTTP handler goroutine crashes the entire process (Go's runtime terminates on unrecovered panics in goroutines, not just the current goroutine). Frameworks like gin and echo include automatic panic recovery middleware, but the standard `net/http` does not. Additionally, returning `err.Error()` from database or filesystem operations in HTTP responses exposes internal paths, table names, query structure, and OS information.

**References:** CWE-209, CWE-248

### Mandatory Rules

- **Add panic-recovery middleware to all `net/http` servers** — gin and echo include this by default; for `net/http` and chi, implement it explicitly.
- **In goroutines spawned with `go func()`**, add `defer func() { if r := recover(); r != nil { ... } }()` to prevent process termination.
- **Return generic error messages to clients** — use a correlation/request ID in the response body so users can report issues without exposing internal details.
- **Log detailed errors server-side** with the request ID, stack trace, and full error chain — never discard errors silently.
- **Never return `err.Error()` from database, file system, or internal service calls** directly in HTTP responses — these typically contain table names, file paths, or internal hostnames.

```go
// ❌ INSECURE — stack trace and file path returned to client
func handler(w http.ResponseWriter, r *http.Request) {
    data, err := os.ReadFile(path)
    if err != nil {
        http.Error(w, err.Error(), http.StatusInternalServerError)
        // exposes: "open /var/data/secrets.db: permission denied"
    }
}

// ✅ SECURE — generic message to client; detailed error logged with request ID
func handler(w http.ResponseWriter, r *http.Request) {
    data, err := os.ReadFile(path)
    if err != nil {
        reqID := r.Header.Get("X-Request-ID")
        slog.Error("file read failed", "error", err, "request_id", reqID, "path", path)
        http.Error(w, "internal server error", http.StatusInternalServerError)
        return
    }
    w.Write(data)
}

// ✅ SECURE — recovery middleware for net/http (add as outermost handler)
import "runtime/debug"

func recoveryMiddleware(next http.Handler) http.Handler {
    return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        defer func() {
            if rec := recover(); rec != nil {
                slog.Error("panic recovered",
                    "error", rec,
                    "stack", string(debug.Stack()),
                    "method", r.Method,
                    "path", r.URL.Path,
                )
                http.Error(w, "internal server error", http.StatusInternalServerError)
            }
        }()
        next.ServeHTTP(w, r)
    })
}
```

---

## 19. Regex — Attacker-Controlled Patterns

**Vulnerability:** Go uses the RE2 engine, which guarantees linear-time matching and is immune to catastrophic backtracking (unlike PCRE-based engines). However, `regexp.MustCompile(userPattern)` panics on invalid regex syntax — a single malformed pattern from user input crashes the process. Very large patterns or inputs also consume proportional CPU and memory, enabling resource exhaustion even without backtracking.

**References:** CWE-1333, CWE-400

### Mandatory Rules

- **Never compile user-supplied regex patterns** — compile only constants at package initialization time with `regexp.MustCompile`.
- **If user-supplied patterns are a product requirement**, use `regexp.Compile` (returns an error instead of panicking) and enforce strict length limits on both the pattern (e.g., max 200 bytes) and the input string.
- **Limit input string length before matching** — even linear RE2 matching consumes time and memory proportional to input size; cap at a reasonable maximum (e.g., 10 KB for most validation use cases).
- **Apply rate limiting on endpoints** that perform regex matching on user input — even linear-time matching can be used for resource exhaustion at scale.

```go
// ❌ INSECURE — panics on invalid pattern (DoS vector); allows long patterns (resource exhaustion)
pattern := r.FormValue("filter")
re := regexp.MustCompile(pattern) // panic if pattern is "(("
matched := re.MatchString(input)

// ❌ INSECURE — compiling inside a hot loop (amplification risk when combined with user input)
for _, item := range items {
    re := regexp.MustCompile(r.FormValue("pattern"))
    if re.MatchString(item) { results = append(results, item) }
}

// ✅ SECURE — compile constants at package init; never use user-supplied patterns
var (
    emailRe    = regexp.MustCompile(`^[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}$`)
    usernameRe = regexp.MustCompile(`^[a-zA-Z0-9_\-]{3,32}$`)
    uuidRe     = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)
)

func validateEmail(email string) bool {
    if len(email) > 254 {
        return false
    }
    return emailRe.MatchString(email)
}

// ✅ SECURE — user-supplied pattern with error handling, length limit, and input cap
func searchWithUserPattern(pattern, input string) (bool, error) {
    if len(pattern) > 200 {
        return false, errors.New("pattern too long")
    }
    if len(input) > 10*1024 {
        return false, errors.New("input too long")
    }
    re, err := regexp.Compile(pattern) // returns error, does not panic
    if err != nil {
        return false, fmt.Errorf("invalid pattern: %w", err)
    }
    return re.MatchString(input), nil
}
```

---

## 20. Supply Chain — Go Modules

**Vulnerability:** An uncommitted `go.sum` file allows the build system to accept any module content that satisfies the version constraint without hash verification. Floating pseudo-versions or `@latest` auto-update to malicious releases between builds. CVE-2021-33196 (archive/zip panic), CVE-2023-24540, CVE-2023-29400 (html/template escaping bypasses), and CVE-2024-34156 (encoding/gob stack exhaustion) were vulnerabilities in the Go standard library itself, demonstrating that even stdlib requires active monitoring.

**References:** CVE-2021-33196, CVE-2023-29400, CWE-494

### Mandatory Rules

- **Commit both `go.mod` and `go.sum`** to version control — `go.sum` contains cryptographic hashes (SHA-256) for every dependency module zip and its `go.mod`; without it, hash checking is bypassed.
- **Run `go mod verify` in CI** before building — verifies that locally cached module downloads match the hashes in `go.sum`; fails if any file has been tampered with.
- **Run `govulncheck ./...` in CI** — queries the Go Vulnerability Database for known CVEs affecting direct and transitive dependencies that are actually called by the code; lower false-positive rate than dependency-list-only scanners.
- **Use specific version tags in `go.mod`** (e.g., `v1.9.1`) for all `require` directives — never use `@latest`, `@master`, or pseudo-versions (`v0.0.0-00010101000000-...`) for external packages.
- **Do not set `GONOSUMDB`, `GONOSUMCHECK`, or `GOFLAGS=-mod=mod` globally in CI** — these disable sum database checking; restrict them to internal-only modules via `GONOSUMDB=*.internal.example.com`.
- **Review transitive dependencies** with `go mod graph` before adding new direct dependencies — a small direct dependency may pull in dozens of transitive packages.

```go
// ❌ INSECURE — go.mod with floating pseudo-version; go.sum absent from repo
// go.mod:
// require github.com/some/lib v0.0.0-00010101000000-000000000000

// ❌ INSECURE — CI pipeline that skips verification
// RUN go build ./...  ← no go mod verify, no govulncheck

// ✅ SECURE — go.mod with explicit semver tags
// go.mod:
// require (
//     github.com/gin-gonic/gin           v1.9.1
//     github.com/golang-jwt/jwt/v5       v5.2.1
//     github.com/jackc/pgx/v5            v5.5.5
//     golang.org/x/crypto                v0.21.0
// )

// ✅ SECURE — CI verification steps (Makefile or GitHub Actions)
// go mod verify           # confirms cached modules match go.sum
// govulncheck ./...       # checks for known CVEs in used code paths
// go test -race ./...     # race detector + unit tests
// go build -trimpath ./... # removes source paths from binary
```

---

## CVE Reference Table

| CVE | Severity | Component | Description | Fixed In |
|-----|----------|-----------|-------------|----------|
| CVE-2024-34156 | High (7.5) | `encoding/gob` | Stack exhaustion via deeply nested structures during decoding; attacker-supplied gob input triggers unbounded recursion | Go 1.23.1 / 1.22.7 |
| CVE-2023-44487 | High (7.5) | `net/http` (HTTP/2) | HTTP/2 Rapid Reset attack — RST_STREAM flood exhausts server resources without completing requests | Go 1.21.3 / 1.20.10 |
| CVE-2023-39325 | High (7.5) | `golang.org/x/net` | HTTP/2 rapid stream reset enables denial of service via resource exhaustion in x/net/http2 | x/net v0.17.0 |
| CVE-2023-29400 | High (7.3) | `html/template` | Improper handling of HTML-like comments in JS template context allows XSS bypass | Go 1.20.4 / 1.19.9 |
| CVE-2023-29197 | High (7.5) | `net/http` | Path traversal in `net/http` file server on Windows via mixed-case or backslash paths | Go 1.20.3 / 1.19.8 |
| CVE-2023-24540 | Critical (9.8) | `html/template` | Improper escaping of JavaScript template literals (backtick strings) allows XSS injection | Go 1.20.3 / 1.19.8 |
| CVE-2022-41723 | High (7.5) | `net/http2` | HPACK bomb — malicious HTTP/2 client sends crafted HPACK headers triggering excessive CPU and memory | Go 1.20 / x/net v0.7.0 |
| CVE-2022-27664 | High (7.5) | `net/http` | Denial of service via persistent connection kept open after TLS handshake error in HTTP/2 server | Go 1.19.1 / 1.18.6 |
| CVE-2021-33196 | High (7.5) | `archive/zip` | Panic on invalid ZIP file with overlapping or out-of-bounds entry offsets | Go 1.16.5 / 1.15.13 |
| CVE-2020-26160 | High (7.7) | `github.com/dgrijalva/jwt-go` | Improper JWT signature verification allows `alg: none` bypass; package unmaintained | Migrate to `golang-jwt/jwt/v5` |

---

## Security Checklist

### Injection (SQL, Command, Template, Header)

- [ ] All `database/sql` queries use parameterized placeholders (`?` or `$1`), never `fmt.Sprintf`
- [ ] GORM `Where`, `Raw`, and `Exec` calls use `?` placeholders, not raw string interpolation
- [ ] Column names and ORDER BY directions from user input are validated against an allowlist
- [ ] `exec.Command` never uses `sh -c` or `bash -c` forms with user-supplied data
- [ ] `exec.Command` first argument (binary name) is a hardcoded constant, not a variable
- [ ] All arguments to `exec.Command` that originate from user input are validated and allowlisted
- [ ] `exec.CommandContext` is used in all HTTP handlers so commands are cancelled with the request
- [ ] `html/template` is used for all HTML output, never `text/template`
- [ ] No casts to `template.HTML`, `template.JS`, `template.URL`, or `template.CSS` from user input
- [ ] Response header values from user input are sanitized to remove `\r`, `\n`, and null bytes
- [ ] `Location` header values validated against the same rules as redirect targets
- [ ] No `fmt.Fprintf(w, "<html>%s</html>", userInput)` patterns in HTTP handlers

### Cryptography and Secrets

- [ ] All security-sensitive random values use `crypto/rand.Read`, never `math/rand`
- [ ] Passwords are hashed with `bcrypt` (cost ≥ 12) or `argon2id`, never SHA-256/MD5/SHA-1 alone
- [ ] Symmetric encryption uses AES-256-GCM; AES-ECB and unauthenticated AES-CBC are absent
- [ ] GCM nonces are generated fresh per encryption operation with `crypto/rand.Read`
- [ ] RSA keys are at least 2048 bits; new code uses ECDSA P-256 or Ed25519
- [ ] No hardcoded secrets, keys, IVs, or salts in source code or committed config files
- [ ] JWT signing secrets loaded from environment variables or secrets manager
- [ ] JWT parsing validates algorithm type explicitly (no `alg: none` acceptance)
- [ ] JWT `exp`, `iss`, and `aud` claims validated on every token verification
- [ ] `dgrijalva/jwt-go` is absent from `go.mod`; replaced by `golang-jwt/jwt/v5`

### Network / HTTP / TLS

- [ ] `http.Server` structs configure `ReadTimeout`, `ReadHeaderTimeout`, `WriteTimeout`, `IdleTimeout`
- [ ] `http.ListenAndServe` (no timeout) is not used in production code
- [ ] All outbound `http.Client` instances have `Timeout` set
- [ ] All outbound requests use `http.NewRequestWithContext` with a context carrying a deadline
- [ ] `tls.Config.InsecureSkipVerify` is never set to `true` in any production code path
- [ ] `tls.Config.MinVersion` is `tls.VersionTLS12` or higher across all TLS configurations
- [ ] Internal service-to-service calls use a custom `RootCAs` pool pinned to the internal CA
- [ ] SSRF: user-supplied URLs are parsed, scheme validated, hostname allowlisted, and IPs checked
- [ ] DNS rebinding protection: resolved IPs checked for private/loopback/link-local ranges
- [ ] HTTP redirects validated with `CheckRedirect` to prevent open redirect via redirect chain
- [ ] Open redirect: post-login `next` parameter validated as relative path starting with `/`, not `//`
- [ ] `http.MaxBytesReader` applied to request bodies before JSON, XML, or multipart parsing
- [ ] `MaxHeaderBytes` is explicitly set on all `http.Server` instances

### Concurrency and Resource Management

- [ ] No map read/write without mutex protection in code reached by concurrent goroutines
- [ ] `sync.RWMutex` or `sync.Map` used for all shared map access patterns
- [ ] `go test -race ./...` runs in CI and passes cleanly
- [ ] All `context.WithCancel` and `context.WithTimeout` calls have `defer cancel()` immediately after
- [ ] All `resp.Body` closures use `defer resp.Body.Close()` after successful `client.Do`
- [ ] `io.LimitReader` wraps all stream reads of user-supplied or external data
- [ ] Goroutines spawned with `go func()` have panic recovery via `defer recover()`
- [ ] Recovery middleware applied to all `net/http` handler chains
- [ ] Resource limits (goroutine pools, semaphores) set for workloads with fan-out patterns
- [ ] `goleak.VerifyNone(t)` or equivalent used in test suite to catch goroutine leaks

### Input Validation and Parsing

- [ ] All JSON API handlers use `json.Decoder.DisallowUnknownFields()`
- [ ] JSON decoding uses typed structs, not `interface{}`, for security-sensitive data
- [ ] Large integers decoded via typed struct fields (`int64`) or `json.Decoder.UseNumber()`
- [ ] XML input size limited with `http.MaxBytesReader` before decoding
- [ ] Uploaded file paths validated with `filepath.Base` and checked for `..` and path separators
- [ ] All file opens after `filepath.Join` verified with `filepath.EvalSymlinks` + prefix check
- [ ] User-supplied regex patterns rejected; only constants compiled at init via `regexp.MustCompile`
- [ ] Integer arithmetic with user-controlled operands is bounds-checked before multiplication
- [ ] Integer casts (e.g., `int64` to `int32`) are range-checked before the cast
- [ ] All user input validated at entry point (controller/handler) before business logic

### Error Handling and Logging

- [ ] Sensitive struct fields implement `LogValue() slog.Value` or `String() string` with redaction
- [ ] `r.Header` is never logged directly; only allowlisted header names are logged
- [ ] Request/response bodies are not logged in production without PII redaction
- [ ] URL query parameters containing `password`, `token`, `key`, or `secret` are redacted in logs
- [ ] All errors handled explicitly; `_` is not used to discard error returns from security-sensitive calls
- [ ] Error messages returned in HTTP responses are generic (no file paths, table names, or stack traces)
- [ ] `err.Error()` from database, filesystem, or internal services never written to HTTP response body
- [ ] Structured logging (`slog`) used with severity levels; correlation IDs included in all log entries
- [ ] Panics in HTTP handlers are caught by recovery middleware and return 500, not crash the process

### Supply Chain

- [ ] `go.sum` is committed to the repository alongside `go.mod`
- [ ] `go mod verify` runs in CI before the build step
- [ ] `govulncheck ./...` runs in CI and blocks merges on known-exploitable CVEs
- [ ] All `require` directives in `go.mod` use specific semver tags, not `@latest` or pseudo-versions
- [ ] `GONOSUMDB` and `GONOSUMCHECK` are not set globally in CI; restricted to internal modules only
- [ ] New dependencies reviewed for maintenance status, license, and known vulnerabilities before adoption
- [ ] `go build -trimpath` used for release builds to remove source file paths from the binary
- [ ] `go mod graph` reviewed before adding dependencies to understand transitive pull-in

---

## Tooling

| Tool | Purpose | Command |
|------|---------|---------|
| [`go vet`](https://pkg.go.dev/cmd/vet) | Built-in static analysis; detects suspicious constructs (incorrect Printf formats, unreachable code, mutex copies) | `go vet ./...` |
| [`staticcheck`](https://staticcheck.dev) | Advanced static analysis; finds bugs, deprecated API usage, unnecessary code, and correctness issues | `staticcheck ./...` |
| [`govulncheck`](https://pkg.go.dev/golang.org/x/vuln/cmd/govulncheck) | Queries Go Vulnerability Database for CVEs in direct and transitive deps actually called by the code | `govulncheck ./...` |
| [`gosec`](https://github.com/securego/gosec) | Security-focused static analysis; detects hardcoded credentials, SQL injection, weak crypto, shell injection | `gosec ./...` |
| [`golangci-lint`](https://golangci-lint.run) | Aggregated linter runner combining go vet, staticcheck, gosec, errcheck, and 50+ other linters in one pass | `golangci-lint run` |
| [`go test -race`](https://go.dev/doc/articles/race_detector) | Runtime race detector; instruments memory accesses to find concurrent map/slice races missed by code review | `go test -race ./...` |
| [`go mod verify`](https://go.dev/ref/mod#go-mod-verify) | Verifies downloaded module contents match `go.sum` cryptographic hashes; catches supply-chain tampering | `go mod verify` |
| [`trivy`](https://trivy.dev) | Filesystem and container image scanner; checks Go binaries and `go.mod` for known CVEs | `trivy fs .` |
| [`nancy`](https://github.com/sonatype-nexus-community/nancy) | Sonatype OSS Index scanner for Go modules; flags packages with known vulnerabilities | `go list -json -deps ./... \| nancy sleuth` |
| [`semgrep`](https://semgrep.dev) | Pattern-based static analysis; Go ruleset covers SSRF, SQL injection, command injection, and insecure crypto | `semgrep --config=p/golang` |
| [`goleak`](https://github.com/uber-go/goleak) | Goroutine leak detection in tests; asserts no unexpected goroutines remain after each test case | `goleak.VerifyNone(t)` in `TestMain` |
| [`go build -trimpath`](https://pkg.go.dev/cmd/go) | Removes absolute source file paths from compiled binary, preventing path disclosure in stack traces | `go build -trimpath ./...` |
| [`go build -race`](https://go.dev/doc/articles/race_detector) | Builds binary with race detector instrumentation enabled for staging environment testing | `go build -race ./...` |
