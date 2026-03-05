# 🐘 PHP Security Rules

> **Standard:** PHP 8.x Language & Standard Library Security
> **Sources:** OWASP PHP Security Cheat Sheet, PHP Security Advisories, NIST NVD, CVE Details, phpsecurity.readthedocs.io
> **Version:** 1.0.0
> **Last updated:** March 2026
> **Scope:** PHP 8.x language and built-in extensions — no framework-specific rules

---

## General Instructions

Apply these rules to all PHP code. Many vulnerabilities in PHP arise from type coercion, unsafe defaults, or misuse of built-in functions. Follow the mandatory rules and use the ✅/❌ examples as references for secure vs insecure patterns.

---

## 1. Type Juggling

**Vulnerability:** PHP's loose comparison operator `==` performs type coercion, enabling authentication bypasses and logic flaws. Strings starting with `0e` are treated as scientific notation (zero) in PHP < 8.0, making MD5 or SHA1 hash comparisons exploitable with "magic hashes."

**References:** CWE-704, PHP type juggling authentication bypass (OWASP), multiple CTF and real-world auth bypasses

### Mandatory Rules

- **Always use strict comparison `===`** for equality checks, especially in authentication, token validation, and conditional logic.
- **Never compare password hashes or tokens with `==`** — always use `hash_equals()` for timing-safe comparison.
- **Never use `==` to compare user-controlled strings against integers** — `"1abc" == 1` is `true` in PHP.
- Be aware that `in_array()` and `array_search()` use loose comparison by default — always pass `true` as the third argument for strict mode.
- **Never use MD5 or SHA1** for password hashing or security tokens; even strict comparison cannot mitigate their cryptographic weakness.

```php
// ❌ INSECURE — loose comparison, magic hash bypass
$hash = md5($input); // e.g., "240610708" → "0e462097431906509019562988736854"
if ($hash == "0e...") { ... } // True! Both treated as 0

// ❌ INSECURE — type coercion in auth
if ($userToken == $storedToken) { ... } // "0" == false == null == ""

// ❌ INSECURE — in_array with loose comparison
$allowedIds = [0, 1, 2];
if (in_array("admin", $allowedIds)) { ... } // True! "admin" == 0

// ✅ SECURE — strict comparison
if ($userToken === $storedToken) { ... }

// ✅ SECURE — timing-safe comparison for secrets
if (!hash_equals($storedToken, $userToken)) {
    throw new InvalidArgumentException('Token mismatch');
}

// ✅ SECURE — strict in_array
if (in_array($value, $allowedIds, true)) { ... }
```

---

## 2. Deserialization — unserialize() and PHAR Archives

**Vulnerability:** PHP's `unserialize()` instantiates arbitrary classes and calls magic methods (`__wakeup`, `__destruct`, `__toString`). Attackers craft Property-Oriented Programming (POP) chains to achieve Remote Code Execution. PHAR archives trigger deserialization via file operations using the `phar://` stream wrapper.

**References:** CWE-502, CVE-2024-5932 (GiveWP RCE via unserialize, CVSS 10.0), CVE-2024-24842 (Ecwid RCE), CVE-2023-1405 (Formidable Forms RCE), PHP 8.0 improved `phar://` security

### Mandatory Rules

- **Never pass user-controlled data to `unserialize()`** — there is no safe way to deserialize untrusted PHP serialized objects.
- Use **JSON (`json_encode`/`json_decode`)** for data interchange with external systems.
- If deserialization is unavoidable, use the **`allowed_classes` option** to whitelist a strict set of classes: `unserialize($data, ['allowed_classes' => [MyClass::class]])`.
- **Never use `phar://` stream wrappers on user-supplied paths** — even in read operations like `file_exists()`, `is_file()`, `getimagesize()`, or `hash_file()`.
- Validate and sanitize file paths before any filesystem functions if user input is involved.
- Audit third-party libraries for gadget chains using tools like PHPGGC.

```php
// ❌ INSECURE — arbitrary class instantiation + POP chain execution
$obj = unserialize($_COOKIE['session']); // RCE if POP chain exists

// ❌ INSECURE — phar:// triggering deserialization via file op
$exists = file_exists($_GET['path']); // Attacker sends phar:///tmp/evil.phar/x

// ✅ SECURE — use JSON instead
$data = json_decode($_COOKIE['session'], true);
if (json_last_error() !== JSON_ERROR_NONE) {
    throw new RuntimeException('Invalid session data');
}

// ✅ SECURE — restrict classes if unserialize is unavoidable
$obj = unserialize($data, ['allowed_classes' => [SafeClass::class]]);

// ✅ SECURE — block phar:// by validating scheme
function safeFilePath(string $path): string {
    if (preg_match('/^[a-zA-Z]+:\/\//', $path)) {
        throw new InvalidArgumentException('Stream wrappers are not allowed');
    }
    return realpath($path) ?: throw new InvalidArgumentException('Invalid path');
}
```

---

## 3. SQL Injection

**Vulnerability:** Concatenating user input into SQL queries allows attackers to manipulate query logic, extract data, and in some configurations execute OS commands.

**References:** CWE-89, OWASP SQL Injection, PHP Data Objects (PDO) documentation

### Mandatory Rules

- **Always use PDO with prepared statements and bound parameters** for all database queries.
- **Never interpolate user input into SQL strings** — not even with `addslashes()` or `mysqli_real_escape_string()`.
- Use **allowlists** for dynamic column/table names — never interpolate them from user input.
- Set PDO error mode to `PDO::ERRMODE_EXCEPTION` and never expose raw SQL errors to users.
- Use the principle of least privilege for database accounts — read-only credentials for read-only operations.

```php
// ❌ INSECURE — SQL injection via string concatenation
$query = "SELECT * FROM users WHERE id = " . $_GET['id'];
$result = $pdo->query($query);

// ❌ INSECURE — still vulnerable, escaping is fragile
$id = $pdo->quote($_GET['id']);
$query = "SELECT * FROM users WHERE id = $id"; // Multi-byte encoding bypasses possible

// ✅ SECURE — PDO prepared statement
$stmt = $pdo->prepare('SELECT * FROM users WHERE id = :id AND active = :active');
$stmt->execute([':id' => (int)$_GET['id'], ':active' => 1]);
$user = $stmt->fetch(PDO::FETCH_ASSOC);

// ✅ SECURE — allowlist for dynamic column names
$allowedColumns = ['name', 'email', 'created_at'];
$column = $_GET['sort'];
if (!in_array($column, $allowedColumns, true)) {
    $column = 'name'; // fallback to safe default
}
$stmt = $pdo->prepare("SELECT * FROM users ORDER BY {$column} ASC");
```

---

## 4. Cross-Site Scripting (XSS)

**Vulnerability:** Rendering user-supplied data in HTML without escaping allows attackers to inject malicious scripts that execute in victims' browsers, enabling session theft, credential phishing, and account takeover.

**References:** CWE-79, OWASP XSS Prevention Cheat Sheet

### Mandatory Rules

- **Always escape output** with `htmlspecialchars($var, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8')` when rendering untrusted data in HTML.
- **Never use `echo` directly on user input** — even for attributes, URLs, or JavaScript contexts.
- For JavaScript contexts, use JSON encoding: `json_encode($var, JSON_HEX_TAG | JSON_HEX_APOS | JSON_HEX_AMP | JSON_HEX_QUOT)`.
- **Set a Content Security Policy (CSP) header** to restrict script sources.
- Mark session cookies as `HttpOnly` and `Secure` to mitigate XSS session theft.
- Sanitize HTML content (e.g., user-generated rich text) with a dedicated library like HTML Purifier — never with regex.

```php
// ❌ INSECURE — direct echo of user input
echo "Hello, " . $_GET['name'];
echo "<input value='" . $_GET['query'] . "'>";

// ❌ INSECURE — JavaScript context without proper encoding
echo "<script>var user = '" . $username . "';</script>";

// ✅ SECURE — escape for HTML context
echo "Hello, " . htmlspecialchars($_GET['name'], ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');

// ✅ SECURE — escape for HTML attribute
echo '<input value="' . htmlspecialchars($value, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8') . '">';

// ✅ SECURE — escape for JavaScript context
echo "<script>var user = " . json_encode($username, JSON_HEX_TAG | JSON_HEX_APOS | JSON_HEX_AMP | JSON_HEX_QUOT) . ";</script>";

// ✅ SECURE — CSP header
header("Content-Security-Policy: default-src 'self'; script-src 'self'; object-src 'none'");
```

---

## 5. Cross-Site Request Forgery (CSRF)

**Vulnerability:** Forged cross-origin requests can trigger state-changing actions (fund transfers, password changes) using the victim's authenticated session if not protected by CSRF tokens.

**References:** CWE-352, OWASP CSRF Prevention Cheat Sheet

### Mandatory Rules

- **Generate a cryptographically secure CSRF token** per session using `random_bytes(32)` or `bin2hex(random_bytes(32))`.
- **Include the CSRF token in all state-changing forms** (POST, PUT, DELETE) and verify it server-side.
- Set session cookies with **`SameSite=Strict` or `SameSite=Lax`** to prevent cross-site cookie sending.
- **Validate the `Origin` or `Referer` header** as a secondary check for AJAX requests.
- Never rely on checking the request method alone (GET vs POST) as CSRF protection.

```php
// ❌ INSECURE — no CSRF protection
session_start();
if ($_POST['action'] === 'delete_account') {
    deleteAccount($_SESSION['user_id']); // Forgeable from any site
}

// ✅ SECURE — CSRF token generation
session_start();
if (empty($_SESSION['csrf_token'])) {
    $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
}

// ✅ SECURE — CSRF token validation
function validateCsrfToken(string $submittedToken): bool {
    if (empty($_SESSION['csrf_token'])) {
        return false;
    }
    return hash_equals($_SESSION['csrf_token'], $submittedToken);
}

if (!validateCsrfToken($_POST['csrf_token'] ?? '')) {
    http_response_code(403);
    exit('CSRF token invalid');
}

// ✅ SECURE — SameSite cookie in php.ini or at runtime
session_set_cookie_params([
    'lifetime' => 0,
    'path'     => '/',
    'domain'   => '',
    'secure'   => true,
    'httponly' => true,
    'samesite' => 'Strict',
]);
```

---

## 6. Command Injection

**Vulnerability:** Passing user input to shell execution functions (`exec`, `shell_exec`, `system`, `passthru`, `proc_open`, `popen`) allows OS command injection, leading to full server compromise.

**References:** CWE-78, OWASP Command Injection

### Mandatory Rules

- **Avoid shell execution functions entirely** when native PHP functions or libraries exist (e.g., use `imagecreatefrompng()` instead of calling ImageMagick via shell).
- If shell execution is required, **always escape arguments with `escapeshellarg()`** — never `escapeshellcmd()` alone.
- **Use explicit command paths** (`/usr/bin/convert`) and avoid interpreting user-supplied command names.
- **Validate all inputs against a strict allowlist** before they touch shell functions.
- Consider using `proc_open()` with an **array argument** (where available) to avoid shell interpretation entirely.
- Never pass user-controlled data to `eval()`, `assert()` (PHP < 8.0 with string argument), or `preg_replace()` with the `/e` modifier.

```php
// ❌ INSECURE — direct injection via filename
$filename = $_GET['file'];
system("convert $filename output.jpg"); // Attacker sends: "x; rm -rf /"

// ❌ INSECURE — escapeshellcmd is insufficient for arguments
$safe = escapeshellcmd($_GET['file']); // Does not prevent adding extra args
system("convert $safe output.jpg");

// ✅ SECURE — escapeshellarg for each argument
$filename = escapeshellarg($_GET['file']);
system("/usr/bin/convert $filename /var/output/output.jpg");

// ✅ SECURE — allowlist validation + escapeshellarg
$allowed = ['jpg', 'png', 'gif'];
$ext = strtolower(pathinfo($_GET['file'], PATHINFO_EXTENSION));
if (!in_array($ext, $allowed, true)) {
    throw new InvalidArgumentException('File type not allowed');
}
$filename = escapeshellarg('/uploads/' . basename($_GET['file']));
exec("/usr/bin/convert $filename /var/output/out.jpg");

// ✅ SECURE — proc_open with array (no shell)
$process = proc_open(
    ['/usr/bin/convert', '-resize', '200x200', $inputPath, $outputPath],
    [1 => ['pipe', 'w'], 2 => ['pipe', 'w']],
    $pipes
);
```

---

## 7. File Inclusion — LFI and RFI

**Vulnerability:** Using user-controlled values in `include`, `require`, `include_once`, or `require_once` enables Local File Inclusion (LFI) — reading sensitive system files or executing uploaded content — and Remote File Inclusion (RFI) — executing attacker-hosted scripts.

**References:** CWE-98, OWASP File Inclusion, OWASP Testing Guide v4.2 §4.7.11.1

### Mandatory Rules

- **Never pass user input to `include`, `require`, `include_once`, or `require_once`**.
- Use an **allowlist of safe identifiers** mapped to file paths — never build paths dynamically from user input.
- Set `allow_url_include = Off` in `php.ini` (disabled by default since PHP 7.4, removed in PHP 8.0).
- Set `open_basedir` in `php.ini` to restrict filesystem access to the application directory.
- Validate all file paths with `realpath()` and confirm they remain within the expected base directory.

```php
// ❌ INSECURE — direct LFI/RFI
include $_GET['page'];                     // LFI: ?page=/etc/passwd
include "pages/" . $_GET['page'] . ".php"; // LFI: ?page=../../../../etc/passwd%00

// ❌ INSECURE — RFI (if allow_url_include = On)
include "http://" . $_GET['host'] . "/evil.php";

// ✅ SECURE — allowlist of safe templates
$allowedPages = [
    'home'    => 'templates/home.php',
    'about'   => 'templates/about.php',
    'contact' => 'templates/contact.php',
];
$page = $_GET['page'] ?? 'home';
if (!isset($allowedPages[$page])) {
    $page = 'home'; // Fallback to safe default
}
include $allowedPages[$page];

// ✅ SECURE — realpath validation
function safeInclude(string $userInput, string $baseDir): void {
    $resolved = realpath($baseDir . '/' . $userInput . '.php');
    if ($resolved === false || strncmp($resolved, $baseDir, strlen($baseDir)) !== 0) {
        throw new RuntimeException('Invalid file path');
    }
    include $resolved;
}
```

---

## 8. File Upload Security

**Vulnerability:** Unrestricted file uploads allow attackers to upload PHP web shells, execute server-side code, or overwrite critical files.

**References:** CWE-434, OWASP Unrestricted File Upload, OWASP File Upload Cheat Sheet

### Mandatory Rules

- **Validate file type by MIME type using `finfo_file()`** — never trust `$_FILES['file']['type']` (user-controlled).
- **Allowlist permitted extensions and MIME types** — reject everything else.
- **Rename uploaded files** with a UUID or hash — never use the original filename.
- **Store uploaded files outside the web root** (e.g., `/var/uploads/` instead of `/var/www/html/uploads/`).
- If files must be web-accessible, serve them through a PHP controller that sets correct content-type headers.
- Disable PHP execution in upload directories via `.htaccess` (`php_flag engine off` or deny pattern).
- Check file size limits to prevent DoS via large uploads.

```php
// ❌ INSECURE — trust user-supplied MIME type and use original filename
$uploadDir = '/var/www/html/uploads/';
$filename = $_FILES['upload']['name'];
move_uploaded_file($_FILES['upload']['tmp_name'], $uploadDir . $filename);

// ❌ INSECURE — extension check only (bypassed by "shell.php.jpg")
$ext = pathinfo($_FILES['upload']['name'], PATHINFO_EXTENSION);
if ($ext === 'jpg') { ... } // Attacker uploads "evil.php%00.jpg"

// ✅ SECURE — MIME type validation via finfo + allowlist + rename + outside web root
$allowedMimes = ['image/jpeg', 'image/png', 'image/gif', 'image/webp'];
$allowedExts  = ['jpg', 'jpeg', 'png', 'gif', 'webp'];
$uploadDir    = '/var/uploads/'; // Outside web root

$tmpPath = $_FILES['upload']['tmp_name'];
$origName = $_FILES['upload']['name'];
$ext = strtolower(pathinfo($origName, PATHINFO_EXTENSION));

// Validate extension
if (!in_array($ext, $allowedExts, true)) {
    http_response_code(400);
    exit('File type not allowed');
}

// Validate actual MIME type
$finfo = new finfo(FILEINFO_MIME_TYPE);
$mime  = $finfo->file($tmpPath);
if (!in_array($mime, $allowedMimes, true)) {
    http_response_code(400);
    exit('File type not allowed');
}

// Validate size
if ($_FILES['upload']['size'] > 5 * 1024 * 1024) { // 5 MB
    http_response_code(400);
    exit('File too large');
}

// Generate safe filename
$safeFilename = bin2hex(random_bytes(16)) . '.' . $ext;
move_uploaded_file($tmpPath, $uploadDir . $safeFilename);
```

---

## 9. XML External Entity (XXE) Injection

**Vulnerability:** PHP's XML libraries (SimpleXML, DOMDocument, XMLReader) are vulnerable to XXE by default when external entity processing is enabled. Attackers use XXE to read local files, perform SSRF, or cause DoS (Billion Laughs attack).

**References:** CWE-611, CVE-2024-45293 (phpoffice/phpspreadsheet XXE), CVE-2024-52596 (SimpleSAMLphp XXE — auth bypass), CVE-2023-3823 (PHP libxml XXE)

### Mandatory Rules

- **Call `libxml_disable_entity_loader(true)` before parsing any XML** (required for PHP < 8.0; in PHP 8.0+ it is disabled by default but still good practice).
- **Use `LIBXML_NOENT` cautiously** — it resolves entities and is dangerous with untrusted input. Never use it on user-supplied XML.
- Do **not** use `LIBXML_DTDLOAD` or `LIBXML_DTDVALID` on untrusted XML.
- Prefer JSON over XML for data interchange with external parties.
- Validate and sanitize XML from external sources; use an XML schema (XSD) to restrict allowed elements.

```php
// ❌ INSECURE — default DOMDocument allows XXE
$dom = new DOMDocument();
$dom->loadXML($userXml); // Reads /etc/passwd via <!ENTITY xxe SYSTEM "file:///etc/passwd">

// ❌ INSECURE — LIBXML_NOENT resolves entities (dangerous)
$dom->loadXML($userXml, LIBXML_NOENT);

// ✅ SECURE — disable external entity loading (PHP < 8.0)
libxml_disable_entity_loader(true);
$dom = new DOMDocument();
$dom->loadXML($userXml, LIBXML_NONET); // LIBXML_NONET blocks network access

// ✅ SECURE — PHP 8.0+ (entity loader disabled by default) + defensive flags
$dom = new DOMDocument();
$dom->loadXML($userXml, LIBXML_NONET | LIBXML_NOCDATA);
// Do NOT pass LIBXML_NOENT

// ✅ SECURE — SimpleXML with entity disabled
libxml_disable_entity_loader(true);
$xml = simplexml_load_string($userXml);

// ✅ SECURE — XMLReader
$reader = new XMLReader();
$reader->xml($userXml, null, LIBXML_NONET);
```

---

## 10. Cryptography

**Vulnerability:** Using weak hashing algorithms (MD5, SHA1), insecure random number generators (`rand()`, `mt_rand()`), deprecated encryption (`mcrypt`, ECB mode), or weak key derivation leads to authentication bypass, credential theft, and data exposure.

**References:** CWE-327, CWE-330, CWE-916, PHP `password_hash()` documentation, OpenSSL PHP manual

### Mandatory Rules

**Password Hashing:**
- **Always use `password_hash($password, PASSWORD_ARGON2ID)`** (PHP 7.3+) or `PASSWORD_DEFAULT` which defaults to bcrypt.
- **Always use `password_verify($input, $hash)`** to verify — never compare hashes directly.
- **Never use MD5, SHA1, SHA256, or SHA512 alone for password hashing** — they are too fast for this purpose.
- Use `password_needs_rehash()` to upgrade hashes when algorithm or cost factors change.

**Cryptographically Secure Random:**
- **Always use `random_bytes(int $length)`** for secure random bytes.
- **Always use `random_int(int $min, int $max)`** for secure random integers.
- **Never use `rand()`, `mt_rand()`, `array_rand()`, `shuffle()`, or `str_shuffle()`** for security-sensitive operations.

**Symmetric Encryption:**
- Use **AES-256-GCM** (authenticated encryption) via `openssl_encrypt()` — it provides both confidentiality and integrity.
- **Never use ECB mode** — it leaks patterns. Prefer GCM over CBC.
- Always use a **unique, random IV** for each encryption operation.
- **Never use `mcrypt`** — deprecated since PHP 7.1, removed in PHP 7.2.

**Key Derivation:**
- For deriving keys from passwords, use `hash_pbkdf2('sha256', $password, $salt, 100000, 32)` or Argon2 via `password_hash()`.
- **Never use a user's password directly as an encryption key** without key derivation.

```php
// ❌ INSECURE — MD5 for passwords
$hash = md5($password);

// ❌ INSECURE — insecure random token
$token = md5(rand());

// ❌ INSECURE — ECB mode leaks patterns
$encrypted = openssl_encrypt($data, 'AES-256-ECB', $key);

// ✅ SECURE — Argon2id password hashing
$hash = password_hash($password, PASSWORD_ARGON2ID);
if (!password_verify($input, $hash)) {
    throw new RuntimeException('Invalid credentials');
}
// Upgrade hash if needed
if (password_needs_rehash($hash, PASSWORD_ARGON2ID)) {
    $hash = password_hash($newPassword, PASSWORD_ARGON2ID);
    // Save new hash to DB
}

// ✅ SECURE — cryptographically secure token
$token = bin2hex(random_bytes(32));

// ✅ SECURE — AES-256-GCM (authenticated encryption)
function encrypt(string $plaintext, string $key): string {
    $iv         = random_bytes(12); // 96 bits for GCM
    $tag        = '';
    $ciphertext = openssl_encrypt($plaintext, 'aes-256-gcm', $key, OPENSSL_RAW_DATA, $iv, $tag);
    if ($ciphertext === false) {
        throw new RuntimeException('Encryption failed');
    }
    return base64_encode($iv . $tag . $ciphertext);
}

function decrypt(string $encoded, string $key): string {
    $raw        = base64_decode($encoded, true);
    $iv         = substr($raw, 0, 12);
    $tag        = substr($raw, 12, 16);
    $ciphertext = substr($raw, 28);
    $plaintext  = openssl_decrypt($ciphertext, 'aes-256-gcm', $key, OPENSSL_RAW_DATA, $iv, $tag);
    if ($plaintext === false) {
        throw new RuntimeException('Decryption failed — possible tampering');
    }
    return $plaintext;
}
```

---

## 11. Session Security

**Vulnerability:** Predictable session IDs, session fixation, and insecure cookie attributes allow session hijacking and impersonation.

**References:** CWE-384, CWE-614, OWASP Session Management Cheat Sheet

### Mandatory Rules

- **Call `session_regenerate_id(true)` after any privilege change** (login, sudo, role change) to prevent session fixation.
- **Never accept session IDs from GET parameters** — only use cookies.
- Set all session cookies with **`HttpOnly`, `Secure`, and `SameSite=Strict`**.
- **Set a reasonable session timeout** and destroy sessions on logout with `session_destroy()`.
- Configure `session.use_strict_mode = 1` in `php.ini` to reject uninitialized session IDs.
- Store sensitive session data server-side only — never in the cookie payload.

```php
// ❌ INSECURE — session ID not regenerated after login
session_start();
if (validCredentials($_POST['user'], $_POST['pass'])) {
    $_SESSION['user'] = $_POST['user']; // Session fixation possible
}

// ❌ INSECURE — accept session from GET (session hijacking via URL sharing)
session_id($_GET['PHPSESSID']);
session_start();

// ✅ SECURE — regenerate ID after login, secure cookie settings
session_set_cookie_params([
    'lifetime' => 0,
    'path'     => '/',
    'domain'   => '',
    'secure'   => true,   // HTTPS only
    'httponly' => true,   // No JavaScript access
    'samesite' => 'Strict',
]);
session_start();

if (validCredentials($_POST['user'], $_POST['pass'])) {
    session_regenerate_id(true); // Invalidate old session
    $_SESSION['user_id'] = $userId;
    $_SESSION['role']    = $role;
}

// ✅ SECURE — logout
function logout(): void {
    session_start();
    $_SESSION = [];
    session_destroy();
    setcookie(session_name(), '', time() - 3600, '/');
}
```

---

## 12. Path Traversal

**Vulnerability:** Building filesystem paths from user input without validation allows attackers to access files outside the intended directory using `../` sequences.

**References:** CWE-22, OWASP Path Traversal

### Mandatory Rules

- **Always validate paths with `realpath()`** and confirm the result starts with the expected base directory.
- Use **`basename()`** to strip directory components from user-supplied filenames.
- **Never build paths by concatenating user input** with directory strings without validation.
- Set `open_basedir` in `php.ini` to restrict PHP's filesystem access to the application directory.

```php
// ❌ INSECURE — path traversal via user input
$file = '/var/www/files/' . $_GET['filename']; // ?filename=../../etc/passwd
readfile($file);

// ❌ INSECURE — basename helps but not sufficient if extension is appended
$file = '/var/www/files/' . basename($_GET['filename']) . '.pdf'; // Encoding tricks possible

// ✅ SECURE — realpath validation
function safeReadFile(string $userFilename, string $baseDir): string {
    // Strip directory components from input first
    $clean    = basename($userFilename);
    $fullPath = realpath($baseDir . DIRECTORY_SEPARATOR . $clean);

    if ($fullPath === false) {
        throw new RuntimeException('File not found');
    }

    // Ensure the resolved path is within the allowed directory
    $baseDir = realpath($baseDir);
    if (strncmp($fullPath, $baseDir . DIRECTORY_SEPARATOR, strlen($baseDir) + 1) !== 0) {
        throw new RuntimeException('Access denied: path traversal detected');
    }

    return file_get_contents($fullPath);
}
```

---

## 13. PHP-CGI and Server Configuration

**Vulnerability:** Misconfigured PHP-CGI or FastCGI deployments expose the PHP binary to argument injection. CVE-2024-4577 is a critical bypass of the CVE-2012-1823 fix that allows unauthenticated RCE on Windows systems via Unicode soft hyphen (U+00AD) to hyphen mapping.

**References:** CVE-2024-4577 (CVSS 9.8 — PHP-CGI argument injection, fixed in PHP 8.1.29/8.2.20/8.3.8), CVE-2012-1823, mass exploitation by TellYouThePass ransomware (June 2024)

### Mandatory Rules

- **Upgrade to PHP 8.1.29, 8.2.20, or 8.3.8+** immediately if running PHP-CGI on Windows.
- **Avoid PHP-CGI deployment** — prefer PHP-FPM with a reverse proxy.
- Disable direct access to `php.exe` or `php-cgi.exe` from the web server if PHP-CGI is required.
- Configure the web server to block query strings that begin with `-` for PHP-CGI endpoints.
- **Never expose `phpinfo()`** in production — it reveals php.ini settings, loaded extensions, and environment variables.
- Remove or restrict access to default PHP diagnostic files.

```nginx
# ✅ SECURE — Nginx: block argument injection for PHP-CGI
location ~ \.php$ {
    # Block query strings starting with hyphen (CVE-2024-4577 / CVE-2012-1823)
    if ($query_string ~ "^[^=&]*-") {
        return 400;
    }
    fastcgi_pass php-fpm:9000; # Use PHP-FPM, not PHP-CGI
}
```

---

## 14. php.ini Security Configuration

**Vulnerability:** Default or misconfigured `php.ini` settings expose sensitive information, enable dangerous features, and widen the attack surface.

**References:** PHP Security Manual, OWASP PHP Configuration Cheat Sheet

### Mandatory Rules

Set the following `php.ini` directives in production:

```ini
; ❌ INSECURE defaults that must be changed
; expose_php = On        → reveals PHP version in HTTP headers
; display_errors = On    → leaks stack traces to users
; allow_url_fopen = On   → enables URL-based file operations (SSRF risk)
; allow_url_include = On → enables RFI (removed in PHP 8.0)
; session.use_strict_mode = 0 → allows uninitialized session IDs

; ✅ SECURE production settings
expose_php             = Off
display_errors         = Off
log_errors             = On
error_log              = /var/log/php/error.log
allow_url_fopen        = Off   ; disable unless required for specific functionality
allow_url_include      = Off   ; always Off (default)
open_basedir           = /var/www/html:/tmp
session.use_strict_mode = 1
session.cookie_httponly = 1
session.cookie_secure   = 1
session.cookie_samesite = Strict
session.use_only_cookies = 1
session.gc_maxlifetime  = 1440
file_uploads           = On    ; restrict with upload_max_filesize and post_max_size
upload_max_filesize    = 5M
post_max_size          = 8M
max_execution_time     = 30
memory_limit           = 128M
disable_functions      = exec,shell_exec,system,passthru,proc_open,popen,pcntl_exec
```

---

## 15. PHP-Specific Language Pitfalls

### 15.1 `extract()` and Variable Variables (`$$var`)

**Vulnerability:** `extract()` converts array keys into variable names in the current scope, allowing attackers to overwrite superglobals (`$_SESSION`, `$_SERVER`) and other critical variables. Variable variables (`$$var`) let user input reference any variable in memory.

**References:** CWE-454, CWE-473, PHP manual — extract()

#### Mandatory Rules

- **Never call `extract()` on user-supplied arrays** (`$_GET`, `$_POST`, `$_COOKIE`, `$_REQUEST`, `$_FILES`).
- **Never use `$$userInput`** or `$$_GET[...]` in any context.
- If `extract()` is needed on trusted data, use the `EXTR_PREFIX_ALL` or `EXTR_PREFIX_SAME` flags to avoid collisions.

```php
// ❌ INSECURE — attacker sends ?_SESSION[admin]=1, overwriting $_SESSION
extract($_GET);

// ❌ INSECURE — variable variable from user input
$var = $_GET['key'];
echo $$var; // Attacker sends ?key=_SESSION to dump session data

// ✅ SECURE — access specific keys explicitly
$page  = (int) ($_GET['page'] ?? 1);
$order = in_array($_GET['order'] ?? '', ['asc', 'desc'], true)
    ? $_GET['order']
    : 'asc';

// ✅ SECURE — extract with prefix on trusted config arrays only
extract($config, EXTR_PREFIX_ALL, 'cfg');
// Keys become $cfg_host, $cfg_port, etc. — no collisions
```

---

### 15.2 Backtick Operator

**Vulnerability:** PHP's backtick operator (`` `command` ``) is syntactic sugar for `shell_exec()` and executes operating system commands. It is easy to miss in code review.

**References:** CWE-78, PHP manual — Execution Operators

#### Mandatory Rules

- **Never use the backtick operator** in application code — treat it identically to `shell_exec()`.
- Enable static analysis rules (Psalm, PHPStan, PHPCS Security Audit) that flag backtick usage.
- If shell execution is required, use `proc_open()` with an array argument (see Section 6).

```php
// ❌ INSECURE — executes shell command; easy to miss in reviews
$output = `ls -la $userInput`;

// ❌ INSECURE — equivalent to shell_exec, attacker controls $filename
$result = `convert $filename output.jpg`;

// ✅ SECURE — use proc_open with array (no shell, no injection)
$process = proc_open(
    ['/bin/ls', '-la', $safePath],
    [1 => ['pipe', 'w'], 2 => ['pipe', 'w']],
    $pipes
);
```

---

### 15.3 `assert()` with String Argument (PHP < 8.0)

**Vulnerability:** In PHP < 8.0, `assert()` accepts a string argument and evaluates it as PHP code, equivalent to `eval()`. This is a common source of RCE when user input reaches `assert()`.

**References:** CWE-95, PHP manual — assert() (string evaluation deprecated in PHP 7.2, removed in PHP 8.0)

#### Mandatory Rules

- **Never pass user-controlled data to `assert()`**.
- For PHP < 8.0 codebases, treat `assert($stringExpr)` as equivalent to `eval($stringExpr)` in security reviews.
- Enable `assert.exception = 1` and `zend.assertions = -1` (disabled) in production `php.ini`.

```php
// ❌ INSECURE — PHP < 8.0: evaluates arbitrary PHP code
assert($_GET['condition']); // RCE: ?condition=system('id')

// ❌ INSECURE — chained from user input
$check = $_POST['check'];
assert("strlen($check) > 0"); // RCE via: ') || system('id') || strlen('

// ✅ SECURE — assertions only with boolean expressions (PHP 8.0+)
assert(count($items) > 0); // Boolean, not a string

// ✅ SECURE — php.ini for production
// zend.assertions = -1   (disables assertions entirely in production)
// assert.exception = 1   (throws AssertionError instead of warning)
```

---

### 15.4 `preg_replace()` with `/e` Modifier (PHP < 7.0)

**Vulnerability:** The `/e` modifier caused `preg_replace()` to evaluate the replacement string as PHP code after substitution. This allowed RCE when user input influenced the pattern or replacement.

**References:** CWE-95, CVE-2014-8639, removed in PHP 7.0

#### Mandatory Rules

- **Never use the `/e` modifier in any PHP version** (it was removed in PHP 7.0 but may exist in legacy code).
- Replace `preg_replace('/pattern/e', $replacement, $subject)` with `preg_replace_callback()`.
- Audit legacy codebases for any `/e` usage — it is a critical RCE vector.

```php
// ❌ INSECURE — PHP < 7.0: executes $replacement as PHP code
$output = preg_replace('/(.*)/e', $_GET['replace'], $input);
// Attacker sends: replace=system('id')

// ✅ SECURE — use preg_replace_callback instead
$output = preg_replace_callback(
    '/(\d+)/',
    fn($matches) => $matches[1] * 2,
    $input
);
```

---

### 15.5 PHP Stream Wrappers (LFI Bypass Vectors)

**Vulnerability:** PHP supports many stream wrappers beyond `phar://`. Several are commonly used to bypass LFI mitigations or achieve RCE: `data://` (embed inline content), `expect://` (execute commands if the `expect` extension is loaded), `zip://` (read from ZIP archives), and `php://filter` (read and encode file contents including PHP source).

**References:** CWE-98, OWASP LFI, PHP manual — Supported Protocols and Wrappers

#### Mandatory Rules

- **Block all stream wrappers in user-supplied paths** — not just `phar://`.
- Validate that user-supplied paths do not contain `://` (any scheme).
- Disable dangerous wrappers in `php.ini`:
  - `allow_url_fopen = Off` — disables `http://`, `ftp://` wrappers in file functions
  - `allow_url_include = Off` — disables remote includes (default Off; removed in PHP 8.0)
- Use `open_basedir` to restrict filesystem scope.

```php
// ❌ INSECURE — php://filter reads any file (including PHP source)
// ?page=php://filter/convert.base64-encode/resource=config.php
include $_GET['page'];

// ❌ INSECURE — data:// embeds inline PHP execution (if allow_url_include = On)
// ?page=data://text/plain;base64,PD9waHAgc3lzdGVtKCdpZCcpOw==
include $_GET['page'];

// ❌ INSECURE — expect:// executes OS commands (if expect extension loaded)
// ?page=expect://id
include $_GET['page'];

// ✅ SECURE — block all stream wrappers before using user input in file ops
function validateNoWrapper(string $input): void {
    if (preg_match('#[a-zA-Z][a-zA-Z0-9+\-.]*://#', $input)) {
        throw new InvalidArgumentException('Stream wrappers are not allowed');
    }
}

// ✅ SECURE — allowlist approach (no dynamic path building)
$allowed = ['home', 'about', 'contact'];
$page    = $_GET['page'] ?? 'home';
if (!in_array($page, $allowed, true)) {
    $page = 'home';
}
include 'templates/' . $page . '.php';
```

---

### 15.6 `mail()` Header Injection

**Vulnerability:** PHP's `mail()` function accepts a fifth parameter (`$additional_parameters`) appended to the MTA command line. If user input reaches this parameter, attackers can inject arguments (e.g., `-X /var/www/html/shell.php`) to write web shells or redirect mail.

**References:** CWE-88, CWE-74, PHP Bug #29358, Phar/mail() injection gadgets

#### Mandatory Rules

- **Sanitize the fifth `mail()` parameter** — never allow user input to reach `$additional_parameters`.
- **Validate all mail headers** (To, Cc, Bcc, Subject) for CRLF (`\r\n`) characters to prevent header injection.
- Prefer dedicated mail libraries (PHPMailer, Symfony Mailer, SwiftMailer) over `mail()` — they handle escaping correctly.
- Use `filter_var($email, FILTER_VALIDATE_EMAIL)` before using an email address in mail headers.

```php
// ❌ INSECURE — attacker sends: email=-X/var/www/html/shell.php as $to
mail($to, 'Subject', $body, '', "-f $to"); // Injects MTA arg

// ❌ INSECURE — header injection via CRLF in subject
// Attacker sends: Subject = "Hello\r\nBcc: attacker@evil.com"
mail($to, $_POST['subject'], $body);

// ✅ SECURE — validate email and strip CRLF from all header values
function safeMail(string $to, string $subject, string $body): bool {
    if (!filter_var($to, FILTER_VALIDATE_EMAIL)) {
        throw new InvalidArgumentException('Invalid email address');
    }
    // Strip CRLF from subject to prevent header injection
    $subject = str_replace(["\r", "\n"], '', $subject);

    // Never pass user input as 5th argument
    return mail($to, $subject, $body);
}

// ✅ BETTER — use PHPMailer or Symfony Mailer instead of mail()
```

---

### 15.7 `switch` Statement and Loose Comparison

**Vulnerability:** PHP's `switch` statement uses loose comparison (`==`) internally for its case matching, identical to the `==` operator. This creates the same type juggling vulnerabilities as direct loose comparisons.

**References:** CWE-704, PHP manual — switch

#### Mandatory Rules

- **Treat `switch` as if it uses `==`** — never switch on user-supplied values compared against security-relevant cases.
- Prefer explicit `if/elseif` chains with `===` for security checks, or use a match expression (PHP 8.0+) which uses strict comparison.
- When switching on user input for routing or role checks, validate and cast the input type first.

```php
// ❌ INSECURE — switch uses ==, so switch("0") matches case 0:
switch ($_GET['role']) {
    case 0:  grantGuestAccess(); break;
    case 1:  grantUserAccess(); break;
    case 'admin': grantAdminAccess(); break; // "admin" == 0 is true in PHP < 8
}

// ❌ INSECURE — "1e1" == 10 due to numeric conversion
switch ($_GET['code']) {
    case 10: processSpecialCode(); break;
}

// ✅ SECURE — PHP 8.0+ match expression uses strict comparison (===)
$role = $_GET['role'] ?? '';
match (true) {
    $role === 'admin' => grantAdminAccess(),
    $role === 'user'  => grantUserAccess(),
    default           => grantGuestAccess(),
};

// ✅ SECURE — explicit strict checks with if/elseif
$role = $_GET['role'] ?? '';
if ($role === 'admin') {
    grantAdminAccess();
} elseif ($role === 'user') {
    grantUserAccess();
} else {
    grantGuestAccess();
}
```

---

## 16. Supply Chain and Dependency Security

**Vulnerability:** PHP packages from Packagist may contain malicious code, have known CVEs, or be abandoned, introducing vulnerabilities through the dependency tree.

**References:** CWE-1357, Composer Security Advisories, CVE-2021-29472 (Composer RCE via path traversal)

### Mandatory Rules

- **Run `composer audit`** regularly and in CI/CD pipelines to check for known vulnerabilities in dependencies.
- **Commit `composer.lock`** to version control to ensure reproducible, pinned builds.
- Use **`composer install --no-dev`** in production to exclude development dependencies.
- Pin major versions in `composer.json` and review changelogs before upgrading.
- Avoid `eval()` or dynamic code generation in any Composer package.
- Review `post-install-cmd` and `post-update-cmd` scripts in `composer.json` — they execute code on install.

```bash
# ✅ SECURE — audit dependencies for known CVEs
composer audit

# ✅ SECURE — install with locked versions (no updates)
composer install --no-dev --optimize-autoloader

# ✅ SECURE — check for outdated packages
composer outdated --direct
```

---

## CVE Reference Table

| CVE | Severity | Component | Description | Fixed In |
|-----|----------|-----------|-------------|----------|
| CVE-2024-4577 | Critical (9.8) | PHP-CGI (Windows) | Argument injection via Unicode soft hyphen → RCE | PHP 8.1.29, 8.2.20, 8.3.8 |
| CVE-2024-5932 | Critical (10.0) | GiveWP plugin | PHP Object Injection via `unserialize()` + POP chain → RCE | GiveWP 3.14.2 |
| CVE-2024-45293 | High | phpoffice/phpspreadsheet | XXE via XmlScanner → local file disclosure | phpspreadsheet 2.3.0 |
| CVE-2024-47873 | High | phpoffice/phpspreadsheet | XXE in XLSX parsing → file disclosure | phpspreadsheet 2.3.2 |
| CVE-2024-52596 | Critical | SimpleSAMLphp | XXE → read config files, bypass authentication | SimpleSAMLphp 2.10.4 |
| CVE-2024-24842 | High | Ecwid plugin | PHP Object Injection → RCE | Ecwid 6.12.6 |
| CVE-2023-1405 | High | Formidable Forms | PHP Object Injection → RCE | Formidable Forms 6.2 |
| CVE-2023-3823 | High | PHP libxml | XXE injection via external entity expansion | PHP 8.0.30, 8.1.22, 8.2.8 |
| CVE-2021-29472 | High | Composer | Path traversal in VCS URL → RCE | Composer 1.10.22, 2.0.13 |
| CVE-2012-1823 | Critical | PHP-CGI | Argument injection → RCE (original; CVE-2024-4577 bypasses its fix) | PHP 5.3.12, 5.4.2 |

---

## Security Checklist

Use this checklist before deploying PHP applications:

### Type Safety
- [ ] All equality comparisons use `===` (strict)
- [ ] `hash_equals()` used for token/hash comparisons
- [ ] `in_array()` uses `true` as third argument for strict mode

### Deserialization
- [ ] `unserialize()` never receives user-controlled data
- [ ] If `unserialize()` is required, `allowed_classes` allowlist is set
- [ ] No `phar://` wrapper used with user-controlled paths

### Injection
- [ ] All DB queries use PDO prepared statements with bound parameters
- [ ] All shell commands escape arguments with `escapeshellarg()`
- [ ] Backtick operator (`` ` ``) never used in application code
- [ ] No `include`/`require` with user-controlled paths
- [ ] No stream wrappers (`://`) in user-supplied file paths
- [ ] All HTML output escaped with `htmlspecialchars(..., ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8')`
- [ ] CSRF tokens on all state-changing forms
- [ ] `libxml_disable_entity_loader(true)` before parsing XML (PHP < 8.0)
- [ ] `mail()` 5th parameter never accepts user input; Subject/To headers stripped of CRLF

### PHP Language Pitfalls
- [ ] `extract()` never called on `$_GET`, `$_POST`, `$_COOKIE`, `$_REQUEST`, or `$_FILES`
- [ ] No variable variables (`$$var`) with user-controlled input
- [ ] `assert()` never receives string argument from user input
- [ ] No `preg_replace()` with `/e` modifier in codebase
- [ ] Security comparisons use `match` or `if/===` instead of `switch`

### File Operations
- [ ] Uploaded files validated by MIME type (finfo), not user-supplied type
- [ ] Uploaded files renamed and stored outside web root
- [ ] File paths validated with `realpath()` against base directory

### Cryptography
- [ ] `password_hash()` with `PASSWORD_ARGON2ID` for passwords
- [ ] `password_verify()` for password checks
- [ ] `random_bytes()` / `random_int()` for all security tokens
- [ ] AES-256-GCM for symmetric encryption (not ECB)
- [ ] No MD5 or SHA1 for security purposes

### Session
- [ ] `session_regenerate_id(true)` called after login
- [ ] Session cookies: HttpOnly, Secure, SameSite=Strict
- [ ] `session.use_strict_mode = 1` in php.ini
- [ ] `session.use_only_cookies = 1` in php.ini

### Configuration
- [ ] `expose_php = Off` in php.ini
- [ ] `display_errors = Off` in php.ini
- [ ] `allow_url_fopen = Off` (unless required)
- [ ] `open_basedir` configured
- [ ] `disable_functions` includes dangerous shell functions
- [ ] PHP version is current and patched (no EOL versions)
- [ ] `phpinfo()` disabled in production

### Dependencies
- [ ] `composer audit` passes with no high/critical issues
- [ ] `composer.lock` committed to version control
- [ ] No dev dependencies in production (`--no-dev`)

---

## Tooling

| Tool | Purpose | Command |
|------|---------|---------|
| [Psalm](https://psalm.dev/) | Static analysis — type safety, taint tracking | `vendor/bin/psalm --taint-analysis` |
| [PHPStan](https://phpstan.org/) | Static analysis — type errors, undefined methods | `vendor/bin/phpstan analyse src --level 8` |
| [PHPCS Security Audit](https://github.com/squizlabs/PHP_CodeSniffer) | Sniff for SQL injection, XSS, shell injection | `phpcs --standard=Security src/` |
| [Composer Audit](https://getcomposer.org/doc/03-cli.md#audit) | Dependency vulnerability scanning | `composer audit` |
| [Roave Security Advisories](https://github.com/Roave/SecurityAdvisories) | Composer plugin to block vulnerable packages | Add as `require-dev` |
| [PHPGGC](https://github.com/ambionics/phpggc) | POP chain generator for testing deserialization | `phpggc -l` |
| [Semgrep PHP rules](https://semgrep.dev/r?lang=php) | SAST with PHP security rules | `semgrep --config=p/php-security` |
| [Nikto](https://github.com/sullo/nikto) | Web server/PHP misconfiguration scanner | `nikto -h https://example.com` |
