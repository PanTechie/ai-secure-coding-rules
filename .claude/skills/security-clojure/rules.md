# 🟢 Clojure Security Rules

> **Standard:** Clojure Language & Ecosystem Security
> **Sources:** Clojure Security Advisories, NIST NVD, OWASP Injection Prevention, CVE Details, Ring/Compojure Security Docs, Leiningen Security
> **Version:** 1.0.0
> **Last updated:** March 2026
> **Scope:** Clojure 1.11+ on the JVM. Covers the language, standard library, Ring/Compojure web stack, next.jdbc, and Leiningen/deps.edn tooling. Java interop risks (JNDI, ObjectInputStream, XXE) are covered in `security-jvm` — apply both skills when your Clojure code calls Java libraries directly.

---

## General Instructions

Apply these rules to all Clojure code. The most critical Clojure-specific risk is code execution via `eval` and `read-string` — Clojure's dynamic nature and REPL architecture make these traps easy to fall into. Additional risks arise from nREPL exposure, insecure EDN/Transit deserialization, SQL injection via JDBC wrappers, Ring middleware misconfiguration, and supply chain attacks via Leiningen/deps.edn. Follow the mandatory rules and use the ✅/❌ examples as references.

---

## 1. Code Execution — eval, read-string, load-string

**Vulnerability:** Clojure's `eval`, `load-string`, `load-reader`, and — critically — `clojure.core/read-string` evaluate arbitrary Clojure code from any string. An attacker who controls the input can execute any JVM code, spawn processes, read files, or exfiltrate data. This is the single most exploited class of vulnerability in Clojure applications and the easiest to introduce accidentally.

**References:** CWE-94, CWE-95, OWASP Code Injection

### Mandatory Rules

- **Never call `eval` on user-controlled data** — it executes arbitrary Clojure code with full JVM permissions.
- **Never call `clojure.core/read-string` on untrusted input** — unlike `clojure.edn/read-string`, the core version evaluates reader macros (`#=`, `#_`) and tagged literals that can execute code.
- **Always use `clojure.edn/read-string`** for deserializing data from external sources — it is restricted to EDN types (maps, vectors, strings, numbers, keywords) and does not evaluate code.
- **Never use `load-string`, `load-reader`, or `load-file` with user-supplied content** — all three evaluate the input as Clojure source code.
- If dynamic dispatch on function names is required, use an **explicit allowlist map** rather than resolving symbols from user input.

```clojure
;; ❌ INSECURE — executes arbitrary Clojure/JVM code
(eval (read-string user-input))
;; user-input = "(.. Runtime getRuntime (.exec \"id\"))"  → RCE

;; ❌ INSECURE — clojure.core/read-string evaluates reader macros
(clojure.core/read-string "#=(clojure.java.shell/sh \"id\")")
;; Triggers sh/exec — code execution before the result is used

;; ❌ INSECURE — load-string evaluates as Clojure source
(load-string user-supplied-code)

;; ❌ INSECURE — resolving symbols from user input
(let [f (resolve (symbol user-fn-name))]
  (f args)) ;; user-fn-name = "clojure.java.shell/sh" → OS command

;; ✅ SECURE — clojure.edn/read-string: data only, no code execution
(require '[clojure.edn :as edn])
(edn/read-string user-input) ;; Returns data; throws on reader macros

;; ✅ SECURE — allowlist map for dynamic dispatch
(def ALLOWED-HANDLERS
  {"transform" transform-data
   "validate"  validate-schema
   "filter"    filter-records})

(if-let [handler (get ALLOWED-HANDLERS user-fn-name)]
  (handler args)
  (throw (ex-info "Unknown operation" {:op user-fn-name})))
```

---

## 2. nREPL Exposure

**Vulnerability:** Clojure development environments run an nREPL (Network REPL) server that accepts and evaluates arbitrary Clojure expressions over a TCP connection. If the nREPL port is reachable from the network — even on `0.0.0.0` locally, or exposed via a misconfigured Docker port mapping or cloud firewall rule — any connection can achieve full RCE on the host.

**References:** CWE-668, CWE-284, multiple real-world Clojure server compromises

### Mandatory Rules

- **Never start an nREPL server in production** — nREPL is a development tool; remove all `nrepl` or `cider-nrepl` startup from production entry points.
- **Bind nREPL only to loopback (`127.0.0.1`)** in development — never `0.0.0.0`.
- **Configure firewall rules** to block nREPL ports (default 7000–7888) from any non-loopback interface in all environments.
- If a remote REPL is operationally necessary, tunnel it over **SSH** — never expose it directly on the network.
- Audit `project.clj` and `deps.edn` aliases to confirm nREPL is not started by default main entry points.

```clojure
;; ❌ INSECURE — binds to all interfaces, no auth
(require '[nrepl.server :refer [start-server]])
(start-server :port 7888) ;; Listens on 0.0.0.0:7888

;; ❌ INSECURE — Docker Compose exposes port to host network
;; ports:
;;   - "7888:7888"   ← nREPL reachable from host (and beyond, in cloud environments)

;; ✅ SECURE — loopback only, and only in :dev profile
;; project.clj
{:profiles
 {:dev {:repl-options {:host "127.0.0.1"  ;; Loopback only
                       :port 7888}}}}

;; ✅ SECURE — guard nREPL startup with environment check
(when (= (System/getenv "APP_ENV") "development")
  (require '[nrepl.server :refer [start-server]])
  (start-server :bind "127.0.0.1" :port 7888))
;; Production APP_ENV is never "development"
```

---

## 3. EDN and Transit Deserialization

**Vulnerability:** EDN (Extensible Data Notation) supports custom tagged literals (`#my/type {...}`). If a custom reader is registered for a tag, deserializing attacker-controlled EDN can invoke arbitrary constructors or functions. Transit-clj `read` with a custom reader map has the same risk. `nippy` (a popular Clojure serialization library) uses Java serialization under the hood and is vulnerable to gadget chains if `nippy/thaw` is called on untrusted data without a freeze-thaw password.

**References:** CWE-502, CWE-94, EDN Tagged Literals spec, nippy security docs

### Mandatory Rules

- **Use `clojure.edn/read-string` with no custom readers** for untrusted input — the default reader is safe; only extend it with explicitly trusted tagged types.
- If custom EDN tagged literals are needed, **register readers only for types you control** and validate the inner data structure before construction.
- For Transit, use `transit/reader` with an explicit `{:handlers {}}` custom-handler map that allowlists only known safe types.
- **Never call `nippy/thaw` on untrusted bytes** without a `freeze-thaw-password` and `thaw-opts {:check-len? true}` — unprotected nippy is equivalent to Java `ObjectInputStream`.
- Prefer plain EDN or JSON (`cheshire`) for external data interchange.

```clojure
;; ❌ INSECURE — custom reader registered globally; attacker controls #cmd
(require '[clojure.edn :as edn])
(edn/read-string
  {:readers {'cmd clojure.java.shell/sh}}
  "#cmd [\"id\"]") ;; Executes shell command

;; ❌ INSECURE — nippy/thaw without password is Java deserialization
(require '[taoensso.nippy :as nippy])
(nippy/thaw user-bytes) ;; Gadget-chain RCE if bytes are attacker-controlled

;; ✅ SECURE — no custom readers for untrusted input
(edn/read-string user-edn) ;; Safe: only parses data literals

;; ✅ SECURE — nippy with encryption + length check
(nippy/thaw user-bytes
  {:password     [:salted "server-secret-key"]
   :check-len?   true
   :thaw-kv-pair-len-limit 1000})

;; ✅ SECURE — Transit with no custom handlers for untrusted input
(require '[cognitect.transit :as transit])
(let [reader (transit/reader in :json {:handlers {}})]
  (transit/read reader))
```

---

## 4. SQL Injection — next.jdbc and clojure.java.jdbc

**Vulnerability:** Building SQL strings with string interpolation — `str`, `format`, or template strings — and passing them to `jdbc/execute!`, `jdbc/query`, or `next.jdbc/execute!` allows SQL injection. Both `clojure.java.jdbc` and `next.jdbc` support parameterized queries but do not enforce their use.

**References:** CWE-89, OWASP SQL Injection

### Mandatory Rules

- **Always use the vector form** `["SELECT * FROM users WHERE email = ?" email]` for all queries containing user data — the JDBC driver treats the `?` as a bind parameter, never as SQL.
- **Never use `str`, `format`, or `(str "SELECT ... WHERE x = '" val "'")`** to build SQL strings containing external data.
- For dynamic column or table names (which cannot be parameterized), **validate against an explicit allowlist** of known safe identifiers.
- Prefer **HoneySQL** for programmatic query building — it generates parameterized SQL automatically from Clojure data structures.

```clojure
(require '[next.jdbc :as jdbc])
(require '[honey.sql :as sql])

;; ❌ INSECURE — string interpolation → SQL injection
(jdbc/execute! ds
  [(str "SELECT * FROM users WHERE email = '" email "'")])
;; email = "' OR '1'='1" → full table dump

;; ❌ INSECURE — format string
(jdbc/execute! ds
  [(format "SELECT * FROM users WHERE id = %s" user-id)])

;; ✅ SECURE — parameterized vector form (next.jdbc)
(jdbc/execute! ds
  ["SELECT * FROM users WHERE email = ?" email])

;; ✅ SECURE — HoneySQL builds parameterized SQL from data
(jdbc/execute! ds
  (sql/format {:select [:*]
               :from   [:users]
               :where  [:= :email email]}))

;; ✅ SECURE — dynamic ORDER BY with allowlist
(def ALLOWED-SORT-COLS #{"name" "created_at" "email"})

(when-not (ALLOWED-SORT-COLS sort-col)
  (throw (ex-info "Invalid sort column" {:col sort-col})))

(jdbc/execute! ds
  [(str "SELECT * FROM users ORDER BY " sort-col)])
```

---

## 5. Ring / Compojure Web Security

**Vulnerability:** Ring middleware ordering, missing CSRF protection, insecure session configuration, overly permissive CORS, and missing security headers leave Clojure web applications vulnerable to cross-site attacks, session hijacking, and information disclosure.

**References:** CWE-352, CWE-346, CWE-693, OWASP CSRF Prevention, ring-anti-forgery docs

### Mandatory Rules

- **Apply `ring.middleware.defaults/wrap-defaults`** with `site-defaults` (or `api-defaults`) as the base — it includes sensible security defaults including anti-CSRF, secure session, and content-type options.
- **Never disable `ring.middleware.anti-forgery/wrap-anti-forgery`** for browser-facing routes — CSRF tokens are required for all state-changing form/AJAX endpoints.
- **Set session cookie flags**: `:cookie-attrs {:http-only true :secure true :same-site :strict}` in production.
- **Regenerate session on login** — replace the session map contents entirely after authentication to prevent session fixation.
- **Use `ring.middleware.cors`** with an explicit allowlist of permitted origins — never allow `"*"` origins for credentialed requests.
- **Add security headers** via `ring.middleware.not-modified` + manual header middleware or `ring.middleware.defaults`.

```clojure
(require '[ring.middleware.defaults :refer [wrap-defaults site-defaults]])
(require '[ring.middleware.anti-forgery :refer [wrap-anti-forgery]])
(require '[ring.middleware.session :refer [wrap-session]])

;; ❌ INSECURE — bare handler, no security middleware
(def app
  (compojure/routes
    (GET "/" [] "Hello")
    (POST "/transfer" [amount to] (transfer! amount to))))

;; ❌ INSECURE — CSRF disabled, insecure session cookie
(def app
  (-> routes
      (wrap-anti-forgery {:strategy :session-store
                          :error-response (response "Forbidden")})
      (wrap-session {:cookie-name "session"
                     :cookie-attrs {:http-only false  ;; INSECURE
                                    :secure false}})))  ;; INSECURE in prod

;; ✅ SECURE — ring.middleware.defaults site-defaults
(def app
  (wrap-defaults routes
    (-> site-defaults
        (assoc-in [:security :anti-forgery] true)
        (assoc-in [:session :cookie-attrs :secure] true)
        (assoc-in [:session :cookie-attrs :same-site] :strict)
        (assoc-in [:session :cookie-attrs :http-only] true))))

;; ✅ SECURE — explicit security headers middleware
(defn wrap-security-headers [handler]
  (fn [request]
    (-> (handler request)
        (ring.util.response/header "X-Content-Type-Options" "nosniff")
        (ring.util.response/header "X-Frame-Options" "DENY")
        (ring.util.response/header "Referrer-Policy" "strict-origin-when-cross-origin"))))

;; ✅ SECURE — session fixation prevention after login
(defn login-handler [request]
  (let [user (authenticate! (:params request))]
    (-> (ring.util.response/redirect "/dashboard")
        (assoc :session {:user-id (:id user)  ;; Fresh session map
                         :role    (:role user)}))))
```

---

## 6. OS Command Injection — clojure.java.shell and Java Interop

**Vulnerability:** `clojure.java.shell/sh` and direct Java interop (`(.. Runtime getRuntime (.exec ...))`) execute OS commands. Passing user-controlled data to either without strict validation allows command injection.

**References:** CWE-78, OWASP OS Command Injection

### Mandatory Rules

- **Validate all arguments to `clojure.java.shell/sh` against an allowlist** before execution — never pass user-controlled strings directly as shell arguments.
- **Pass arguments as separate strings** to `sh` (varargs form) rather than a single interpolated string — this avoids shell metacharacter interpretation.
- Prefer **Java library alternatives** — `clojure.java.io`, `java.nio.file.Files` instead of `rm`/`cp` shell commands.

```clojure
(require '[clojure.java.shell :refer [sh]])

;; ❌ INSECURE — user controls filename, shell injection possible
(sh "bash" "-c" (str "convert " user-file " output.pdf"))
;; user-file = "x; rm -rf /tmp" → command injection

;; ❌ INSECURE — single-string sh with interpolated input
(sh (str "cat " user-path))

;; ✅ SECURE — varargs form, validated input
(def ALLOWED-FORMATS #{"pdf" "png" "jpg"})

(when-not (ALLOWED-FORMATS output-format)
  (throw (ex-info "Invalid format" {:format output-format})))

(sh "convert" validated-input-path (str "output." output-format))
;; No shell — each argument is a separate process argv element
```

---

## 7. Path Traversal — clojure.java.io

**Vulnerability:** Building file paths from user input with `(io/file base-dir user-input)` or `(str base-dir "/" user-input)` does not prevent `../` traversal. Clojure's `clojure.java.io` delegates to Java's `File` and `Path` APIs, which do not sanitize paths by default.

**References:** CWE-22, OWASP Path Traversal

### Mandatory Rules

- **Canonicalize paths** with `(.getCanonicalPath (io/file ...))` and verify the result starts with the allowed base directory.
- **Reject filenames containing `..`, `/`, `\`, or null bytes** before path construction.
- Rename uploaded files to **server-generated UUIDs** with a validated extension allowlist.

```clojure
(require '[clojure.java.io :as io])

;; ❌ INSECURE — path traversal via io/file
(slurp (io/file upload-dir user-filename))
;; user-filename = "../../etc/passwd" → reads /etc/passwd

;; ✅ SECURE — canonicalize and verify base directory
(defn safe-file-path [base-dir user-filename]
  (when (or (clojure.string/includes? user-filename "..")
            (clojure.string/includes? user-filename "/")
            (clojure.string/includes? user-filename "\0"))
    (throw (ex-info "Invalid filename" {:filename user-filename})))
  (let [base     (.getCanonicalPath (io/file base-dir))
        resolved (.getCanonicalPath (io/file base-dir user-filename))]
    (when-not (clojure.string/starts-with? resolved (str base "/"))
      (throw (ex-info "Path traversal detected" {:path resolved})))
    resolved))

;; ✅ SECURE — rename to UUID on upload
(let [safe-name (str (java.util.UUID/randomUUID) ".pdf")
      dest      (safe-file-path upload-dir safe-name)]
  (io/copy uploaded-stream (io/file dest)))
```

---

## 8. Cryptography

**Vulnerability:** Clojure does not have a built-in cryptography library — all crypto goes through Java interop (`javax.crypto`, `java.security`). The same Java cryptographic pitfalls apply: MD5/SHA-1 for passwords, ECB mode, static IVs, `java.util.Random` for security tokens.

**References:** CWE-327, CWE-328, CWE-330, see also `security-jvm` Section 7

### Mandatory Rules

- **Use AES-256-GCM** (`Cipher/getInstance "AES/GCM/NoPadding"`) for symmetric encryption — not ECB, not DES.
- **Use `java.security.SecureRandom`** for all security-sensitive random values — not `rand`, `rand-int`, `random-uuid` alone for cryptographic tokens.
- **Hash passwords** with `buddy-hashers` (bcrypt/argon2) — never plain `(digest/sha-256 password)`.
- Use constant-time comparison for HMAC/token verification — `(java.security.MessageDigest/isEqual hmac-a hmac-b)`.

```clojure
;; ❌ INSECURE — MD5 hash for password storage
(require '[digest :refer [md5]])
(md5 password)

;; ❌ INSECURE — java.util.Random for session tokens
(.nextLong (java.util.Random.))

;; ✅ SECURE — bcrypt via buddy-hashers
(require '[buddy.hashers :as hashers])
(def hashed (hashers/derive password {:alg :bcrypt+blake2b-512}))
(hashers/check password hashed) ;; => true/false, timing-safe

;; ✅ SECURE — SecureRandom token
(let [bytes (byte-array 32)]
  (.nextBytes (java.security.SecureRandom.) bytes)
  (.encodeToString (java.util.Base64/getUrlEncoder) bytes))

;; ✅ SECURE — AES-256-GCM
(let [key-gen  (doto (javax.crypto.KeyGenerator/getInstance "AES")
                 (.init 256 (java.security.SecureRandom.)))
      key      (.generateKey key-gen)
      iv       (let [b (byte-array 12)]
                 (.nextBytes (java.security.SecureRandom.) b) b)
      cipher   (doto (javax.crypto.Cipher/getInstance "AES/GCM/NoPadding")
                 (.init javax.crypto.Cipher/ENCRYPT_MODE key
                   (javax.crypto.spec.GCMParameterSpec. 128 iv)))]
  (.doFinal cipher plaintext-bytes))
```

---

## 9. Logging and Sensitive Data

**Vulnerability:** Clojure's data-centric style makes it easy to log entire maps — `(log/info "Request:" request-map)` — which may contain `:password`, `:token`, `:api-key`, or `:credit-card-number` fields. `timbre` and `tools.logging` serialize the entire data structure by default.

**References:** CWE-312, CWE-532, OWASP Logging Cheat Sheet

### Mandatory Rules

- **Never log full request maps, user records, or session maps** without first removing sensitive keys.
- Use a **`dissoc` / `select-keys` allowlist projection** before logging any map from an untrusted or sensitive context.
- Use `timbre`'s middleware to install a global **redaction transform** that masks sensitive keys before they reach any appender.
- **Return generic error messages to clients** — log `ex-data` and stack traces server-side only.

```clojure
(require '[taoensso.timbre :as log])

;; ❌ INSECURE — logs entire request including :password, :token
(log/info "User request:" request)
(log/debug "User record:" user-map) ;; Contains :password-hash, :mfa-secret

;; ✅ SECURE — allowlist projection before logging
(log/info "User request:" (select-keys request [:uri :request-method :remote-addr]))

;; ✅ SECURE — global timbre redaction middleware
(def SENSITIVE-KEYS #{:password :token :api-key :secret :credit-card
                      :password-hash :mfa-secret :ssn})

(defn redact-sensitive [data]
  (if (map? data)
    (reduce-kv (fn [m k v]
                 (assoc m k (if (SENSITIVE-KEYS k) "***REDACTED***" v)))
               {} data)
    data))

(log/merge-config!
  {:middleware [(fn [data] (update data :vargs #(map redact-sensitive %)))]})
```

---

## 10. Leiningen and deps.edn Supply Chain

**Vulnerability:** Unpinned dependency versions (`[library "LATEST"]`, `[library "RELEASE"]`), dependency confusion (a malicious package published to Clojars with the same name as an internal artifact), and compromised Clojars packages expose Clojure projects to supply chain attacks. Leiningen plugins run at build time with full JVM permissions.

**References:** CVE-2021-44228 (Log4j — can be a transitive dep), OWASP A06:2021 — Vulnerable and Outdated Components

### Mandatory Rules

- **Pin exact versions** for all dependencies in `project.clj` and `deps.edn` — never use `"LATEST"`, `"RELEASE"`, or version ranges.
- **Audit transitive dependencies** with `lein deps :tree` or `clj -Stree` — check for known-vulnerable libraries (Log4j, commons-collections).
- **Use `lein-nvd`** (OWASP NVD scanner for Leiningen) or `clj-watson` (for deps.edn) in CI.
- **Verify Clojars checksums** — use `lein deps :verify` where available.
- Register your internal group IDs (e.g., `com.yourcompany`) on Clojars to prevent dependency confusion.

```clojure
;; ❌ INSECURE — project.clj with floating versions
:dependencies [[org.clojure/clojure "1.11.1"]
               [ring "LATEST"]                  ;; Unpinned
               [compojure "RELEASE"]            ;; Unpinned
               [cheshire "[1.0,)"]]             ;; Version range

;; ✅ SECURE — exact pinned versions
:dependencies [[org.clojure/clojure "1.11.4"]
               [ring/ring-core "1.12.1"]
               [compojure "1.7.1"]
               [cheshire "5.13.0"]]
```

```edn
;; ❌ INSECURE — deps.edn with LATEST alias
{:deps {org.clojure/clojure {:mvn/version "LATEST"}
        ring/ring-core      {:mvn/version "RELEASE"}}}

;; ✅ SECURE — deps.edn with pinned versions
{:deps {org.clojure/clojure {:mvn/version "1.11.4"}
        ring/ring-core      {:mvn/version "1.12.1"}
        compojure           {:mvn/version "1.7.1"}
        cheshire            {:mvn/version "5.13.0"}}}
```

---

## Java Interop Security Note

Clojure code that uses Java libraries directly may be affected by JVM-level vulnerabilities not covered here. Enable the **`security-jvm`** skill alongside this one when your code involves:

- `ObjectInputStream` / Java native serialization
- `InitialContext.lookup` / JNDI
- `DocumentBuilderFactory` / `SAXParserFactory` / XML parsing
- `Runtime.exec` / `ProcessBuilder`
- Log4j (`log4j-core` via `:dependencies`)
- Spring Framework / Spring Security

---

## CVE Reference Table

| CVE | Severity | Component | Description | Fixed In |
|-----|----------|-----------|-------------|----------|
| CVE-2021-44228 | Critical (10.0) | Apache Log4j 2.x (transitive) | JNDI RCE via logged strings; affects Clojure apps that pull Log4j via Java interop or transitive deps | Log4j 2.17.1 |
| CVE-2022-42889 | Critical (9.8) | Apache Commons Text (transitive) | RCE via `StringSubstitutor` interpolation; can be pulled via Leiningen/Maven transitives | commons-text 1.10.0 |
| CVE-2019-10086 | High (7.3) | Apache Commons BeanUtils 1.x | Arbitrary class access via `PropertyUtils`; affects Clojure apps using beanutils for Java interop | commons-beanutils 1.9.4 |
| CVE-2021-29505 | High (8.8) | XStream (if used via interop) | Deserialization RCE; affects Clojure apps using XStream for Java object serialization | XStream 1.4.17 |
| CVE-2022-24329 | Medium (5.3) | Kotlin stdlib (if Kotlin interop used) | Path traversal in Kotlin stdlib functions; can affect Clojure apps mixing Kotlin dependencies | Kotlin 1.6.21 |

---

## Security Checklist

### Code Execution
- [ ] No `eval` on user-controlled data anywhere in the codebase
- [ ] `clojure.core/read-string` not used on external input — `clojure.edn/read-string` used instead
- [ ] No `load-string`, `load-reader`, or `load-file` on external content
- [ ] Dynamic function dispatch uses allowlist map, not `resolve` on user-supplied names

### nREPL
- [ ] nREPL not started in production entry points
- [ ] nREPL bound to `127.0.0.1` in development (not `0.0.0.0`)
- [ ] Docker/firewall rules block nREPL ports from external access

### Deserialization
- [ ] `clojure.edn/read-string` used without dangerous custom readers for untrusted input
- [ ] `nippy/thaw` called with `:password` and `:check-len? true` for any external bytes
- [ ] Transit reader has no unsafe custom handlers for untrusted data

### SQL Injection
- [ ] All `next.jdbc` / `clojure.java.jdbc` queries use parameterized vector form
- [ ] No `str` or `format` building SQL strings from user input
- [ ] HoneySQL used for programmatic query construction

### Ring / Web
- [ ] `ring.middleware.defaults/site-defaults` or equivalent applied
- [ ] CSRF protection not disabled for browser-facing routes
- [ ] Session cookies: `http-only true`, `secure true`, `same-site :strict`
- [ ] Session map replaced entirely on login (session fixation prevention)
- [ ] CORS allowlist is explicit — not `"*"` for credentialed requests
- [ ] Security headers set: `X-Content-Type-Options`, `X-Frame-Options`

### Cryptography
- [ ] Passwords hashed with `buddy-hashers` (bcrypt/argon2), not digest/sha
- [ ] `java.security.SecureRandom` used for tokens and IVs
- [ ] AES-256-GCM used for symmetric encryption (not DES/ECB)
- [ ] HMAC comparison uses `MessageDigest/isEqual` (timing-safe)

### Logging
- [ ] Full request/user maps not logged directly
- [ ] Sensitive keys (`:password`, `:token`, `:api-key`) redacted before logging
- [ ] Generic error messages returned to clients; full errors only in server logs

### Supply Chain
- [ ] All versions pinned exactly in `project.clj` / `deps.edn`
- [ ] `lein-nvd` or `clj-watson` runs in CI
- [ ] `lein deps :tree` / `clj -Stree` reviewed for vulnerable transitive deps

---

## Tooling

| Tool | Purpose | Command |
|------|---------|---------|
| [lein-nvd](https://github.com/rm-hull/lein-nvd) | OWASP NVD CVE scan for Leiningen projects | `lein nvd check` |
| [clj-watson](https://github.com/clj-holmes/clj-watson) | CVE scan for deps.edn projects | `clj -Tjoplin watson/scan` |
| [clj-holmes](https://github.com/clj-holmes/clj-holmes) | Static analysis: `eval`, `read-string`, SQL injection patterns | `clj-holmes scan -p src/` |
| [eastwood](https://github.com/jonase/eastwood) | Clojure linter — finds suspicious patterns | `lein eastwood` |
| [kibit](https://github.com/jonase/kibit) | Code simplification (catches unsafe idioms) | `lein kibit` |
| [Semgrep Clojure rules](https://semgrep.dev/r#clojure) | Pattern-based security analysis | `semgrep --config "p/clojure"` |
| [Gitleaks](https://gitleaks.io/) | Secret scanning in Git history | `gitleaks detect --source .` |

---

*Released under [CC BY-SA 4.0](https://creativecommons.org/licenses/by-sa/4.0/). Based on Clojure Community Security Advisories, OWASP Injection Prevention Cheat Sheet, Ring/Compojure Security Docs, and NIST/MITRE vulnerability data.*
