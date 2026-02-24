# 🛡️ Code Security Rules — CWE Top 25:2025

> **Version:** 1.0.0
> **Based on:** [CWE Top 25 Most Dangerous Software Weaknesses (2025)](https://cwe.mitre.org/top25/archive/2025/2025_cwe_top25.html)
> **Published by:** MITRE Corporation / CISA
> **Last updated:** February 2026
> **Usage:** Place this file in `.claude/rules/` (Claude Code), `.agent/rules/` (Antigravity), or `.cursor/rules/` (Cursor).

---

## General Instructions

When generating, reviewing, or refactoring code, **always apply the following security rules** based on the 2025 CWE Top 25 Most Dangerous Software Weaknesses. Unlike OWASP (which categorizes risks), CWE identifies **specific, concrete software bugs** — each with a unique identifier, known exploit patterns, and direct coding mitigations. Treat each rule as mandatory. When in doubt, **prioritize defensive coding**.

### How this file complements OWASP

| Focus       | CWE Top 25                            | OWASP Top 10                                                   |
| ----------- | ------------------------------------- | -------------------------------------------------------------- |
| Scope       | Specific code-level bugs              | Broad risk categories                                          |
| Granularity | Single weakness (e.g., CWE-79 = XSS)  | Risk group (e.g., A03 = Injection, covering XSS + SQLi + more) |
| Source data | CVE/NVD real-world vulnerability data | Expert consensus + data analysis                               |
| Use case    | Catch exact bug patterns in code      | Architectural security posture                                 |

Use both together for defense in depth.

---

## Category 1 — Injection & Output Encoding

Injection flaws occur when untrusted data is sent to an interpreter or rendered in output without proper sanitization. This category covers the #1, #2, #9, #10, and #23 most dangerous weaknesses.

### CWE-79 — Cross-Site Scripting (XSS) `[Rank #1]`

Improper neutralization of input during web page generation. Score: 60.38 | KEV: 7

#### Mandatory rules

- **Always encode output contextually** — Use the correct encoding for each output context: HTML entity encoding for HTML body, JavaScript encoding for script contexts, URL encoding for URL parameters, CSS encoding for style contexts. Never rely on a single encoding function for all contexts.
- **Use framework auto-escaping** — Prefer template engines that auto-escape by default (React JSX, Go `html/template`, Jinja2 with `autoescape=True`, Django templates). Never disable auto-escaping without explicit security review.
- **Sanitize HTML when rich content is needed** — When users must submit HTML (e.g., CMS, WYSIWYG), use a proven allowlist-based sanitizer (DOMPurify for JS, Bleach for Python, HtmlSanitizer for .NET). Never use regex-based sanitization.
- **Set Content Security Policy (CSP) headers** — Deploy strict CSP to mitigate impact of XSS. Avoid `unsafe-inline` and `unsafe-eval`. Prefer nonce-based or hash-based script loading.
- **Mark cookies as HttpOnly** — Prevent JavaScript access to session cookies. Combine with `Secure` and `SameSite` attributes.

```python
# ❌ INSECURE — direct interpolation into HTML
def render_greeting(username):
    return f"<h1>Welcome, {username}!</h1>"

# ✅ SECURE — use template engine with auto-escaping
from markupsafe import escape
def render_greeting(username):
    return f"<h1>Welcome, {escape(username)}!</h1>"
```

```typescript
// ❌ INSECURE — innerHTML with user input
element.innerHTML = `<span>${userInput}</span>`;

// ✅ SECURE — textContent (auto-escapes) or framework rendering
element.textContent = userInput;
// Or in React (auto-escapes by default):
return <span>{userInput}</span>;
```

### CWE-89 — SQL Injection `[Rank #2]`

Improper neutralization of special elements used in SQL commands. Score: 28.72 | KEV: 4

#### Mandatory rules

- **Always use parameterized queries** — Use prepared statements or parameterized queries for every SQL operation. Never concatenate or interpolate user input into SQL strings, regardless of input validation applied.
- **Use ORM safe methods** — When using ORMs (SQLAlchemy, Prisma, Django ORM, Entity Framework), use the built-in query builders. Never pass raw user input into `.raw()`, `.execute()`, or `RawSQL()` methods without parameterization.
- **Apply least privilege to database accounts** — Application database users should have only the minimum permissions needed. Never use `root` or `admin` database accounts in application code.
- **Validate input types before queries** — Even with parameterized queries, validate that inputs match expected types (integer IDs, valid enum values, expected string lengths).

```python
# ❌ INSECURE — string concatenation in SQL
def get_user(user_id):
    query = f"SELECT * FROM users WHERE id = {user_id}"
    return db.execute(query)

# ✅ SECURE — parameterized query
def get_user(user_id: int):
    query = "SELECT * FROM users WHERE id = %s"
    return db.execute(query, (user_id,))
```

```typescript
// ❌ INSECURE — template literal in SQL
const user = await db.query(`SELECT * FROM users WHERE id = ${userId}`);

// ✅ SECURE — parameterized query
const user = await db.query("SELECT * FROM users WHERE id = $1", [userId]);
```

### CWE-78 — OS Command Injection `[Rank #9]`

Improper neutralization of special elements used in OS commands. Score: 7.85 | KEV: 20 (highest exploitation rate in Top 25)

#### Mandatory rules

- **Never pass user input to shell commands** — Avoid `os.system()`, `subprocess.run(shell=True)`, `exec()`, backtick operators, and similar functions with user-controlled data. If shell interaction is required, use parameterized APIs that avoid shell interpretation.
- **Use language-native libraries instead of shell commands** — Replace shell commands with library equivalents: use `shutil` instead of `cp`/`mv`, `os.path` instead of shell path operations, `zipfile` instead of `zip`/`unzip`.
- **If shell commands are unavoidable, use allowlists** — Validate arguments against strict allowlists of permitted values. Never rely on denylists or escaping alone.
- **Pass arguments as arrays, not strings** — When using `subprocess.run()` or equivalent, pass arguments as a list of strings, never as a single shell string.

```python
# ❌ INSECURE — shell=True with user input
import subprocess
def convert_file(filename):
    subprocess.run(f"convert {filename} output.pdf", shell=True)

# ✅ SECURE — argument list, no shell
import subprocess
import re
def convert_file(filename: str):
    if not re.match(r'^[a-zA-Z0-9_\-]+\.[a-z]{3,4}$', filename):
        raise ValueError("Invalid filename")
    subprocess.run(["convert", filename, "output.pdf"], shell=False)
```

### CWE-94 — Code Injection `[Rank #10]`

Improper control of code generation. Score: 7.57 | KEV: 7

#### Mandatory rules

- **Never use eval() or equivalent with user input** — Avoid `eval()`, `exec()`, `Function()`, `setTimeout(string)`, `setInterval(string)` with any data derived from user input, request parameters, or external sources.
- **Avoid dynamic code generation** — Do not construct code strings dynamically. Use data-driven approaches (lookup tables, strategy pattern, configuration objects) instead.
- **Restrict template rendering** — Server-side template engines (Jinja2, Twig, Velocity, Freemarker) must not render user-controlled template strings. This prevents Server-Side Template Injection (SSTI).
- **Sandbox unavoidable dynamic execution** — If dynamic code execution is absolutely required (e.g., plugin systems), use sandboxed environments with strict resource limits, no filesystem access, and no network access.

```python
# ❌ INSECURE — eval with user input
def calculate(expression):
    return eval(expression)  # Arbitrary code execution

# ✅ SECURE — restricted math parser
import ast
def calculate(expression: str):
    tree = ast.parse(expression, mode='eval')
    for node in ast.walk(tree):
        if not isinstance(node, (ast.Expression, ast.BinOp, ast.Constant,
                                  ast.Add, ast.Sub, ast.Mult, ast.Div)):
            raise ValueError("Invalid expression")
    return eval(compile(tree, '<string>', 'eval'))
```

### CWE-77 — Command Injection `[Rank #23]`

Improper neutralization of special elements used in a command (broader than OS-specific). Score: 3.15 | KEV: 2

#### Mandatory rules

- **Apply the same protections as CWE-78** — All OS command injection rules apply equally to command injection via other interpreters (LDAP, XPath, SMTP headers, etc.).
- **Sanitize LDAP queries** — Escape special LDAP characters (`*`, `(`, `)`, `\`, `NUL`) in user-supplied values. Use parameterized LDAP search filters where available.
- **Sanitize XPath queries** — Use parameterized XPath or precompiled expressions. Never concatenate user input into XPath strings.
- **Sanitize mail headers** — Validate email headers against injection of newline characters (`\r\n`) that allow injection of additional headers or SMTP commands.

---

## Category 2 — Memory Safety

Memory safety bugs remain the most exploited class of vulnerabilities in native code (C, C++, and similar languages). These weaknesses cause crashes, data leaks, and remote code execution. This category covers #5, #7, #8, #11, #13, #14, and #16.

> **If you are writing in a memory-safe language** (Python, Go, Java, Rust, C#, JavaScript/TypeScript): these rules primarily apply to native extensions, FFI bindings, and unsafe blocks. You still must validate buffer sizes when calling native code.

### CWE-787 — Out-of-Bounds Write `[Rank #5]`

Writing data past the end (or before the beginning) of a buffer. Score: 12.68 | KEV: 12

#### Mandatory rules

- **Always validate buffer sizes before writes** — Check that the destination buffer is large enough before any copy, concatenation, or write operation. Prefer functions that accept explicit size limits.
- **Use safe string functions** — Replace `strcpy` → `strncpy`/`strlcpy`, `strcat` → `strncat`/`strlcat`, `sprintf` → `snprintf`, `gets` → `fgets`. In C++, prefer `std::string` and `std::vector` over raw arrays.
- **Validate array indices** — Before accessing array elements, validate that the index is within the allocated range: `0 <= index < array_size`.
- **Enable compiler protections** — Compile with `-fstack-protector-strong`, `-D_FORTIFY_SOURCE=2`, `-fPIE`, and ASLR. Use AddressSanitizer (`-fsanitize=address`) during testing.

```c
// ❌ INSECURE — no bounds check
void copy_input(char *dest, const char *src) {
    strcpy(dest, src);  // Buffer overflow if src > dest size
}

// ✅ SECURE — bounded copy
void copy_input(char *dest, size_t dest_size, const char *src) {
    strlcpy(dest, src, dest_size);  // Respects buffer limit
}
```

### CWE-416 — Use After Free `[Rank #7]`

Accessing memory after it has been freed. Score: 8.47 | KEV: 14 (second-highest exploitation in Top 25)

#### Mandatory rules

- **Set pointers to NULL after freeing** — Immediately after `free(ptr)`, set `ptr = NULL`. This converts use-after-free into a NULL dereference (crash instead of exploitation).
- **Avoid storing freed pointers** — When freeing an object, ensure no other data structures (lists, trees, caches) retain references to it. Use ownership models.
- **Use smart pointers in C++** — Prefer `std::unique_ptr` (single owner) and `std::shared_ptr` (shared ownership) over raw `new`/`delete`. Avoid `delete` in application code.
- **Use Rust or memory-safe alternatives for new projects** — When starting new native code projects, consider Rust's ownership system, which prevents use-after-free at compile time.

```cpp
// ❌ INSECURE — use after free
void process() {
    char* buffer = (char*)malloc(256);
    // ... use buffer ...
    free(buffer);
    printf("%s", buffer);  // Use after free!
}

// ✅ SECURE — nullify after free + smart pointer alternative
void process_safe_c() {
    char* buffer = (char*)malloc(256);
    // ... use buffer ...
    free(buffer);
    buffer = NULL;  // Prevents use-after-free exploitation
}

// ✅ BETTER — C++ smart pointer
void process_safe_cpp() {
    auto buffer = std::make_unique<char[]>(256);
    // ... use buffer ...
}  // Automatically freed, no dangling pointer possible
```

### CWE-125 — Out-of-Bounds Read `[Rank #8]`

Reading data past the end of a buffer. Score: 7.88 | KEV: 3

#### Mandatory rules

- **Validate read lengths before access** — Before reading from a buffer, verify that the requested offset + length does not exceed the buffer size.
- **Check return values of size functions** — Always check `strlen()`, `sizeof()`, and similar return values before using them as read boundaries.
- **Avoid off-by-one errors** — Strings in C are null-terminated; `strlen("abc")` returns 3 but the buffer needs 4 bytes. Always account for the terminator.
- **Use bounded read functions** — Prefer `strncmp()` over `strcmp()` when comparing against fixed-size buffers. Use `memcmp()` with explicit length.

```c
// ❌ INSECURE — reading without bounds check
void read_data(const char *buf, int offset) {
    char value = buf[offset];  // No size check
}

// ✅ SECURE — bounds-checked read
void read_data(const char *buf, size_t buf_size, size_t offset) {
    if (offset >= buf_size) {
        return;  // Out of bounds
    }
    char value = buf[offset];
}
```

### CWE-120 — Classic Buffer Overflow `[Rank #11]`

Buffer copy without checking input size. Score: 6.96 | KEV: 0

#### Mandatory rules

- **Never use unbounded copy functions** — Eliminate all uses of `gets()`, `strcpy()`, `strcat()`, `sprintf()` in code. These do not check buffer sizes and are inherently unsafe.
- **Always pass destination size** — Every buffer copy function must receive the destination buffer size as a parameter. Use `snprintf(buf, sizeof(buf), ...)`.
- **Prefer stack canaries and ASLR** — Enable `-fstack-protector-strong` and ensure the operating system has ASLR enabled.

### CWE-476 — NULL Pointer Dereference `[Rank #13]`

Accessing memory through a pointer that is NULL. Score: 6.41 | KEV: 0

#### Mandatory rules

- **Always check return values** — Functions that return pointers (`malloc()`, `fopen()`, `strstr()`, `getenv()`) can return NULL. Always check before dereferencing.
- **Validate function parameters** — Public API functions should validate that pointer parameters are not NULL before use. Use assertions or early returns.
- **Use Optional/Result types in modern languages** — In Rust, use `Option<T>` and `Result<T, E>`. In C++17+, use `std::optional`. In Kotlin, use nullable types with safe calls (`?.`).

```c
// ❌ INSECURE — no NULL check
void process(const char *input) {
    size_t len = strlen(input);  // Crash if input is NULL
}

// ✅ SECURE — NULL check before use
void process(const char *input) {
    if (input == NULL) {
        return;
    }
    size_t len = strlen(input);
}
```

### CWE-121 — Stack-Based Buffer Overflow `[Rank #14]`

Writing past a stack-allocated buffer. Score: 5.75 | KEV: 4

#### Mandatory rules

- **Limit stack buffer sizes** — Avoid large stack allocations. For variable-size data, use heap allocation (`malloc`/`new`) with explicit bounds.
- **Never use variable-length arrays (VLAs) with user-controlled sizes** — VLAs in C (e.g., `char buf[n]`) where `n` is user-controlled can overflow the stack. Use fixed sizes or heap allocation.
- **Apply all CWE-787 (out-of-bounds write) rules** — Stack buffer overflows are a specific case of out-of-bounds writes.

### CWE-122 — Heap-Based Buffer Overflow `[Rank #16]`

Writing past a heap-allocated buffer. Score: 5.21 | KEV: 6

#### Mandatory rules

- **Track allocation sizes** — Store the allocated size alongside heap buffers. Always check before writes.
- **Use realloc safely** — When using `realloc()`, check the return value for NULL before discarding the old pointer. On failure, the original memory is not freed.
- **Prefer containers over raw allocation** — In C++, use `std::vector`, `std::string` instead of `malloc`/`new[]`. In Rust, use `Vec<T>`, `String`.
- **Apply all CWE-787 (out-of-bounds write) rules** — Heap overflows are a specific case of out-of-bounds writes.

```c
// ❌ INSECURE — realloc without checking
char *buf = malloc(64);
buf = realloc(buf, new_size);  // If NULL, original memory is leaked
buf[0] = 'A';                  // Potential NULL dereference

// ✅ SECURE — safe realloc pattern
char *buf = malloc(64);
char *tmp = realloc(buf, new_size);
if (tmp == NULL) {
    free(buf);  // Clean up original
    return NULL;
}
buf = tmp;
```

---

## Category 3 — Authorization & Access Control

Authorization failures allow attackers to access resources or perform actions beyond their intended permissions. This category covers #4, #17, #19, #21, and #24.

### CWE-862 — Missing Authorization `[Rank #4]`

No authorization check performed at all. Score: 13.28 | KEV: 0

#### Mandatory rules

- **Every state-changing operation must check authorization** — Before creating, reading, updating, or deleting any resource, verify the authenticated user has permission for that specific operation on that specific resource.
- **Deny by default** — If no authorization rule explicitly grants access, deny the request. Never assume access is permitted because no rule denies it.
- **Centralize authorization logic** — Use a single authorization module or middleware. Never scatter permission checks across individual endpoints.
- **Protect indirect references** — When an API accepts resource IDs from the client, always verify the requesting user owns or has access to that resource (prevent IDOR).

```python
# ❌ INSECURE — no authorization check
@app.route("/api/documents/<doc_id>", methods=["DELETE"])
def delete_document(doc_id):
    db.documents.delete(doc_id)
    return {"status": "deleted"}

# ✅ SECURE — authorization check before action
@app.route("/api/documents/<doc_id>", methods=["DELETE"])
@login_required
def delete_document(doc_id):
    doc = db.documents.get(doc_id)
    if doc is None:
        abort(404)
    if doc.owner_id != current_user.id and not current_user.has_role("admin"):
        abort(403)
    db.documents.delete(doc_id)
    return {"status": "deleted"}
```

### CWE-863 — Incorrect Authorization `[Rank #17]`

Authorization check exists but is implemented incorrectly. Score: 4.14 | KEV: 4

#### Mandatory rules

- **Validate authorization on the server** — Never rely on client-side checks (hidden UI elements, disabled buttons, client-side role checks). The server must enforce all access decisions.
- **Check authorization for every request** — Even if a session was authorized earlier, verify permissions on each request. Roles and permissions can change mid-session.
- **Test authorization edge cases** — Explicitly test: horizontal privilege escalation (user A accessing user B's data), vertical privilege escalation (regular user accessing admin functions), and mixed states (partially revoked permissions).
- **Avoid role comparisons by name string** — Use constants or enums for roles. String comparison (`if role == "admin"`) is fragile and error-prone.

```typescript
// ❌ INSECURE — client-side role check only
if (user.role === "admin") {
  showDeleteButton(); // Button hidden but endpoint unprotected
}

// ✅ SECURE — server-side middleware enforcement
function requireRole(...roles: string[]) {
  return (req: Request, res: Response, next: NextFunction) => {
    if (!req.user || !roles.includes(req.user.role)) {
      return res.status(403).json({ error: "Forbidden" });
    }
    next();
  };
}
app.delete("/api/users/:id", requireRole("admin"), deleteUser);
```

### CWE-284 — Improper Access Control `[Rank #19]`

General access control weakness (parent of CWE-862 and CWE-863). Score: 4.07 | KEV: 1

#### Mandatory rules

- **Apply all CWE-862 and CWE-863 rules** as a baseline.
- **Enforce access control at every layer** — Apply authorization in API gateways, application middleware, and database queries (row-level security). Do not rely on a single layer.
- **Restrict access to administrative interfaces** — Admin panels, management APIs, and debug endpoints must be protected by additional authentication factors and network restrictions (IP allowlists, VPN-only access).
- **Audit access control decisions** — Log all authorization grants and denials with user identity, resource, action, and timestamp. Alert on unusual patterns (repeated 403s, privilege escalation attempts).

### CWE-306 — Missing Authentication for Critical Function `[Rank #21]`

Critical functionality accessible without any authentication. Score: 3.47 | KEV: 11 (high exploitation rate)

#### Mandatory rules

- **Require authentication for all non-public endpoints** — Every API endpoint and server function that accesses private data or performs state changes must verify user identity before processing.
- **Protect administrative and management interfaces** — Configuration pages, API management consoles, health/debug endpoints, and internal dashboards must require authentication. Never expose them publicly.
- **Authenticate API-to-API communication** — Service-to-service calls must use mutual TLS, API keys, or OAuth2 client credentials. Never trust internal network location as authentication.
- **Re-authenticate for sensitive operations** — Password changes, email changes, payment actions, and permission modifications should require re-entry of credentials or step-up authentication.

```python
# ❌ INSECURE — admin function without authentication
@app.route("/admin/reset-database", methods=["POST"])
def reset_database():
    db.reset()
    return {"status": "reset complete"}

# ✅ SECURE — authentication + authorization + re-confirmation
@app.route("/admin/reset-database", methods=["POST"])
@login_required
@require_role("superadmin")
@require_mfa_confirmation
def reset_database():
    audit_log.record("database_reset", user=current_user.id)
    db.reset()
    return {"status": "reset complete"}
```

### CWE-639 — Authorization Bypass Through User-Controlled Key `[Rank #24]`

System uses user-controlled keys (IDs) to look up authorization without verifying ownership. Score: 2.62 | KEV: 0

#### Mandatory rules

- **Never trust client-supplied IDs for authorization** — When a request includes `user_id`, `account_id`, `order_id`, etc., always verify the authenticated user has access to that specific resource. This is the essence of IDOR prevention.
- **Use session-derived identity** — Extract the user identity from the authenticated session/token, not from request parameters. Replace `GET /api/profile?user_id=123` with `GET /api/profile` (user derived from token).
- **Use indirect references** — Map client-visible identifiers to internal IDs server-side. Use UUIDs or random tokens instead of sequential integers for resource identifiers.

```python
# ❌ INSECURE — user_id from request parameter
@app.route("/api/profile")
@login_required
def get_profile():
    user_id = request.args.get("user_id")  # Attacker can change this
    return db.users.get(user_id).to_dict()

# ✅ SECURE — user_id from authenticated session
@app.route("/api/profile")
@login_required
def get_profile():
    return db.users.get(current_user.id).to_dict()
```

---

## Category 4 — File & Resource Handling

Improper handling of files and paths allows attackers to read, write, or execute arbitrary files. This category covers #6 and #12.

### CWE-22 — Path Traversal `[Rank #6]`

Improper limitation of a pathname to a restricted directory. Score: 8.99 | KEV: 10

#### Mandatory rules

- **Canonicalize and validate paths** — Resolve paths to their canonical form (`os.path.realpath()`, `Path.resolve()`) and verify the result is within the expected base directory before any file operation.
- **Never use user input directly in file paths** — Strip or reject `../`, `..\\`, null bytes, and URL-encoded path sequences from user input before constructing paths.
- **Use allowlists for permitted directories** — Define a base directory and verify all resolved paths start with it. Reject any path that escapes the sandbox.
- **Avoid exposing internal file structure** — Use application-generated identifiers (UUIDs, database IDs) instead of filenames in URLs. Map identifiers to actual paths server-side.

```python
# ❌ INSECURE — direct path construction with user input
def serve_file(filename):
    path = f"/var/uploads/{filename}"  # ../../etc/passwd works!
    return open(path).read()

# ✅ SECURE — canonicalization + validation
from pathlib import Path

UPLOAD_DIR = Path("/var/uploads").resolve()

def serve_file(filename: str):
    requested = (UPLOAD_DIR / filename).resolve()
    if not requested.is_relative_to(UPLOAD_DIR):
        raise PermissionError("Path traversal detected")
    if not requested.is_file():
        raise FileNotFoundError()
    return requested.read_text()
```

### CWE-434 — Unrestricted Upload of File with Dangerous Type `[Rank #12]`

Accepting file uploads without proper type validation. Score: 6.87 | KEV: 4

#### Mandatory rules

- **Validate file types server-side** — Check MIME type by inspecting file content (magic bytes), not just the file extension or `Content-Type` header (both are user-controlled).
- **Use an allowlist of permitted types** — Define exactly which file types are accepted. Reject everything else.
- **Rename uploaded files** — Generate random filenames server-side (UUID). Never preserve user-supplied filenames. Strip or replace the extension based on validated type.
- **Store uploads outside the web root** — Uploaded files must not be directly executable by the web server. Serve them through a handler that sets `Content-Disposition: attachment` and correct `Content-Type`.
- **Limit file size** — Enforce maximum file size at both the reverse proxy (nginx/Apache) and application level.
- **Scan uploads for malware** — In sensitive environments, scan uploaded files with antivirus/antimalware before making them available.

```python
# ❌ INSECURE — no type validation, original filename preserved
@app.route("/upload", methods=["POST"])
def upload():
    f = request.files["file"]
    f.save(f"/var/uploads/{f.filename}")  # Path traversal + type bypass
    return {"status": "uploaded"}

# ✅ SECURE — validated, renamed, stored safely
import uuid
import magic

ALLOWED_TYPES = {"image/jpeg", "image/png", "image/gif", "application/pdf"}
MAX_SIZE = 10 * 1024 * 1024  # 10 MB

@app.route("/upload", methods=["POST"])
@login_required
def upload():
    f = request.files["file"]
    content = f.read(MAX_SIZE + 1)
    if len(content) > MAX_SIZE:
        abort(413, "File too large")

    mime = magic.from_buffer(content, mime=True)
    if mime not in ALLOWED_TYPES:
        abort(415, f"Type {mime} not allowed")

    ext = {"image/jpeg": ".jpg", "image/png": ".png",
           "image/gif": ".gif", "application/pdf": ".pdf"}[mime]
    filename = f"{uuid.uuid4()}{ext}"
    Path(f"/var/uploads/{filename}").write_bytes(content)
    return {"id": filename}
```

---

## Category 5 — Data Integrity & Serialization

Trusting serialized data or unvalidated input leads to remote code execution and data corruption. This category covers #15, #18, and #3.

### CWE-502 — Deserialization of Untrusted Data `[Rank #15]`

Deserializing data from untrusted sources without verification. Score: 5.23 | KEV: 11 (high exploitation)

#### Mandatory rules

- **Never deserialize untrusted data with native serializers** — Avoid `pickle` (Python), `ObjectInputStream` (Java), `unserialize()` (PHP), `Marshal.load` (Ruby), `BinaryFormatter` (.NET) on user-controlled input. These allow arbitrary code execution.
- **Use safe data formats** — Prefer JSON, Protocol Buffers, MessagePack, or FlatBuffers for data exchange. These formats do not carry executable code.
- **If native deserialization is required, use allowlists** — Restrict deserializable classes to an explicit allowlist. In Java, use `ObjectInputFilter`. In .NET, use `SerializationBinder`.
- **Validate and sign serialized data** — If you must store serialized objects (e.g., session data), sign them with HMAC before serializing and verify the signature before deserializing.

```python
# ❌ INSECURE — pickle with user data
import pickle
def load_session(data):
    return pickle.loads(data)  # Arbitrary code execution

# ✅ SECURE — JSON with schema validation
import json
from pydantic import BaseModel

class SessionData(BaseModel):
    user_id: int
    role: str
    expires_at: float

def load_session(data: str) -> SessionData:
    return SessionData.model_validate_json(data)
```

```java
// ❌ INSECURE — unrestricted deserialization
ObjectInputStream ois = new ObjectInputStream(inputStream);
Object obj = ois.readObject();  // Arbitrary class instantiation

// ✅ SECURE — allowlist filter (Java 9+)
ObjectInputFilter filter = ObjectInputFilter.Config.createFilter(
    "com.myapp.model.*;!*"  // Allow only app model classes
);
ObjectInputStream ois = new ObjectInputStream(inputStream);
ois.setObjectInputFilter(filter);
Object obj = ois.readObject();
```

### CWE-20 — Improper Input Validation `[Rank #18]`

Insufficient validation of input before processing. Score: 4.09 | KEV: 2

#### Mandatory rules

- **Validate all input on the server** — Never trust client-side validation. Every input reaching the server must be validated for type, length, range, format, and allowed characters.
- **Use allowlists, not denylists** — Define what IS allowed rather than trying to block what isn't. An allowlist of valid characters, values, or patterns is always more secure.
- **Validate before use, not after** — Input must be validated at the point of entry (controller/handler), before it reaches business logic, database queries, or external calls.
- **Reject unexpected input** — If input doesn't match the expected schema, reject it entirely with a clear error message. Do not attempt to "fix" or "sanitize" malformed input and continue processing.

```typescript
// ❌ INSECURE — minimal validation
function updateAge(req: Request) {
  const age = req.body.age; // No validation at all
  db.updateUser(req.user.id, { age });
}

// ✅ SECURE — strict validation with schema
import { z } from "zod";

const UpdateAgeSchema = z.object({
  age: z.number().int().min(0).max(150),
});

function updateAge(req: Request) {
  const { age } = UpdateAgeSchema.parse(req.body); // Throws on invalid
  db.updateUser(req.user.id, { age });
}
```

### CWE-352 — Cross-Site Request Forgery (CSRF) `[Rank #3]`

Forcing authenticated users to submit requests they didn't intend. Score: 13.64 | KEV: 0

#### Mandatory rules

- **Implement CSRF tokens on all state-changing operations** — Every form submission and AJAX call that modifies data must include a unique, unpredictable, per-session CSRF token validated server-side.
- **Use `SameSite` cookie attribute** — Set `SameSite=Lax` (minimum) or `SameSite=Strict` on all authentication cookies. This prevents cookies from being sent on cross-origin requests.
- **Verify Origin/Referer headers** — As defense-in-depth, validate that the `Origin` or `Referer` header matches your domain for state-changing requests.
- **Use framework CSRF middleware** — Enable built-in CSRF protection: Django (`CsrfViewMiddleware`), Express (`csurf` / `csrf-csrf`), Spring (`CsrfFilter`), Laravel (`VerifyCsrfToken`). Never disable it.

```python
# Django — CSRF enabled by default, just don't disable it
# ❌ INSECURE
@csrf_exempt  # Never do this on state-changing views
def transfer_money(request):
    pass

# ✅ SECURE — CSRF middleware active (default in Django)
def transfer_money(request):
    # Django automatically validates CSRF token
    pass
```

---

## Category 6 — Information Exposure

Leaking sensitive data enables further attacks and violates privacy. This category covers #20.

### CWE-200 — Exposure of Sensitive Information `[Rank #20]`

Disclosing information to unauthorized actors. Score: 4.01 | KEV: 1

#### Mandatory rules

- **Never expose stack traces in production** — Configure error handlers to return generic messages to clients. Log detailed errors server-side only. Set `DEBUG=False` in production.
- **Sanitize API responses** — Return only the fields the client needs. Never serialize entire database objects. Use explicit response DTOs/schemas.
- **Remove server identity headers** — Strip `Server`, `X-Powered-By`, `X-AspNet-Version` headers from responses.
- **Protect error messages** — Error messages must not reveal internal architecture, database structure, file paths, SQL queries, or technology stack.
- **Differentiate authentication errors carefully** — Use generic messages like "Invalid credentials" instead of "User not found" vs. "Wrong password" (prevents user enumeration).

```python
# ❌ INSECURE — full exception exposed to client
@app.errorhandler(Exception)
def handle_error(e):
    return {"error": str(e), "trace": traceback.format_exc()}, 500

# ✅ SECURE — generic message, detailed logging
@app.errorhandler(Exception)
def handle_error(e):
    app.logger.exception("Unhandled exception")
    return {"error": "An internal error occurred"}, 500
```

---

## Category 7 — Server-Side Request Forgery

SSRF allows attackers to make the server issue requests to unintended destinations. This category covers #22.

### CWE-918 — Server-Side Request Forgery (SSRF) `[Rank #22]`

Server makes requests to attacker-controlled URLs. Score: 3.36 | KEV: 0

#### Mandatory rules

- **Validate and restrict destination URLs** — Use allowlists of permitted domains, IP ranges, and protocols. Never allow user-controlled URLs to target internal network addresses.
- **Block internal IP ranges** — Deny requests to `127.0.0.0/8`, `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`, `169.254.169.254` (cloud metadata), `fd00::/8`, and `::1`.
- **Resolve DNS before validation** — DNS rebinding attacks can bypass domain allowlists. Resolve the hostname, validate the resulting IP, then connect to that IP.
- **Disable HTTP redirects for server-side requests** — Redirects can lead to internal targets that passed the initial URL validation. If redirects are needed, re-validate each hop.
- **Use a dedicated egress proxy** — Route outbound server-side HTTP requests through a proxy that enforces allowlists and blocks internal destinations.

```python
# ❌ INSECURE — fetch any URL the user provides
import requests
def fetch_url(url):
    return requests.get(url).text  # SSRF to internal services

# ✅ SECURE — allowlist + IP validation
import ipaddress
import socket
import requests

ALLOWED_SCHEMES = {"https"}
BLOCKED_NETWORKS = [
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("169.254.0.0/16"),
]

def fetch_url(url: str) -> str:
    parsed = urllib.parse.urlparse(url)
    if parsed.scheme not in ALLOWED_SCHEMES:
        raise ValueError("Only HTTPS allowed")

    ip = ipaddress.ip_address(socket.gethostbyname(parsed.hostname))
    if any(ip in network for network in BLOCKED_NETWORKS):
        raise ValueError("Internal addresses blocked")

    return requests.get(url, allow_redirects=False, timeout=10).text
```

---

## Category 8 — Resource Management

Failing to limit resource consumption enables denial of service. This category covers #25.

### CWE-770 — Allocation of Resources Without Limits `[Rank #25]`

Allocating resources (memory, CPU, disk, connections) without enforcing limits. Score: 2.54 | KEV: 0

#### Mandatory rules

- **Set maximum sizes for all inputs** — Enforce limits on request body size, file upload size, string lengths, array sizes, and JSON nesting depth.
- **Implement rate limiting** — Apply rate limits per IP, per user, and per API key. Use token bucket or sliding window algorithms.
- **Set timeouts on all operations** — Every database query, HTTP request, file I/O, and external service call must have an explicit timeout. Never use default (infinite) timeouts.
- **Limit concurrent connections** — Configure connection pool maximums for database connections, HTTP client pools, and WebSocket connections.
- **Protect against regex DoS (ReDoS)** — Avoid complex regex with nested quantifiers on user input. Use RE2 or other linear-time regex engines for user-controlled patterns.
- **Paginate query results** — Never return unbounded result sets from database queries. Always enforce `LIMIT` with a maximum page size.

```python
# ❌ INSECURE — unbounded resource usage
@app.route("/search")
def search():
    query = request.args.get("q")
    results = db.execute(f"SELECT * FROM items WHERE name LIKE '%{query}%'")
    return jsonify([r.to_dict() for r in results])  # No limit, no timeout, SQLi

# ✅ SECURE — bounded, paginated, parameterized
MAX_PAGE_SIZE = 100
DEFAULT_TIMEOUT = 5  # seconds

@app.route("/search")
@rate_limit("30/minute")
def search():
    query = request.args.get("q", "")[:200]  # Max input length
    page = min(int(request.args.get("page", 1)), 1000)
    size = min(int(request.args.get("size", 20)), MAX_PAGE_SIZE)
    offset = (page - 1) * size

    results = db.execute(
        "SELECT * FROM items WHERE name LIKE %s LIMIT %s OFFSET %s",
        (f"%{query}%", size, offset),
        timeout=DEFAULT_TIMEOUT
    )
    return jsonify([r.to_dict() for r in results])
```

---

## Quick Reference Table

| Rank | CWE     | Name                         | Category       | KEV | Key Mitigation                                     |
| ---: | ------- | ---------------------------- | -------------- | --: | -------------------------------------------------- |
|    1 | CWE-79  | XSS                          | Injection      |   7 | Output encoding + CSP                              |
|    2 | CWE-89  | SQL Injection                | Injection      |   4 | Parameterized queries                              |
|    3 | CWE-352 | CSRF                         | Data Integrity |   0 | CSRF tokens + SameSite cookies                     |
|    4 | CWE-862 | Missing Authorization        | Access Control |   0 | Deny by default + centralized authz                |
|    5 | CWE-787 | Out-of-Bounds Write          | Memory Safety  |  12 | Bounded copies + safe functions                    |
|    6 | CWE-22  | Path Traversal               | File Handling  |  10 | Canonicalize + validate base dir                   |
|    7 | CWE-416 | Use After Free               | Memory Safety  |  14 | Smart pointers + nullify after free                |
|    8 | CWE-125 | Out-of-Bounds Read           | Memory Safety  |   3 | Bounds check before read                           |
|    9 | CWE-78  | OS Command Injection         | Injection      |  20 | No shell=True + argument arrays                    |
|   10 | CWE-94  | Code Injection               | Injection      |   7 | No eval() + no dynamic code                        |
|   11 | CWE-120 | Classic Buffer Overflow      | Memory Safety  |   0 | Ban unbounded copy functions                       |
|   12 | CWE-434 | Unrestricted File Upload     | File Handling  |   4 | Magic bytes + rename + sandboxed storage           |
|   13 | CWE-476 | NULL Pointer Dereference     | Memory Safety  |   0 | Always check return values                         |
|   14 | CWE-121 | Stack Buffer Overflow        | Memory Safety  |   4 | Fixed-size buffers + no VLAs                       |
|   15 | CWE-502 | Unsafe Deserialization       | Data Integrity |  11 | JSON/Protobuf + no native deserializers            |
|   16 | CWE-122 | Heap Buffer Overflow         | Memory Safety  |   6 | Safe realloc + containers                          |
|   17 | CWE-863 | Incorrect Authorization      | Access Control |   4 | Server-side enforcement + edge case testing        |
|   18 | CWE-20  | Improper Input Validation    | Data Integrity |   2 | Allowlists + schema validation                     |
|   19 | CWE-284 | Improper Access Control      | Access Control |   1 | Multi-layer enforcement                            |
|   20 | CWE-200 | Information Exposure         | Info Exposure  |   1 | Generic errors + response DTOs                     |
|   21 | CWE-306 | Missing Authentication       | Access Control |  11 | Auth on all non-public endpoints                   |
|   22 | CWE-918 | SSRF                         | SSRF           |   0 | Allowlist + block internal IPs                     |
|   23 | CWE-77  | Command Injection            | Injection      |   2 | Same as CWE-78 + interpreter-specific sanitization |
|   24 | CWE-639 | IDOR via User-Controlled Key | Access Control |   0 | Session-derived identity + indirect references     |
|   25 | CWE-770 | Resource Exhaustion          | Resource Mgmt  |   0 | Limits + timeouts + pagination                     |

---

## Cross-Reference: CWE ↔ OWASP Top 10:2025

Many CWEs map to OWASP categories. This shows where our rules overlap and reinforce each other:

| CWE                                                           | OWASP Top 10:2025                                     |
| ------------------------------------------------------------- | ----------------------------------------------------- |
| CWE-79, CWE-89, CWE-78, CWE-94, CWE-77                        | A03 — Injection                                       |
| CWE-862, CWE-863, CWE-284, CWE-639, CWE-306                   | A01 — Broken Access Control                           |
| CWE-787, CWE-416, CWE-125, CWE-120, CWE-121, CWE-122, CWE-476 | A06 — Vulnerable Components (in native libs)          |
| CWE-22, CWE-434                                               | A01 / A05 — Access Control / Misconfiguration         |
| CWE-502                                                       | A08 — Software and Data Integrity Failures            |
| CWE-352                                                       | A01 — Broken Access Control                           |
| CWE-200                                                       | A02 — Cryptographic Failures / A05 — Misconfiguration |
| CWE-918                                                       | A01 — Broken Access Control (SSRF)                    |
| CWE-20                                                        | A03 — Injection (root cause)                          |
| CWE-770                                                       | A05 — Security Misconfiguration                       |

---

## Language-Specific Cheat Sheet

### Memory-Safe Languages (Python, Go, Java, C#, Rust, JS/TS)

Focus on: CWE-79, 89, 352, 862, 863, 22, 434, 502, 94, 78, 918, 200, 306, 639, 770, 20, 77, 284 (18 of 25)

Memory safety CWEs (787, 416, 125, 120, 476, 121, 122) apply only when using FFI, native extensions, or `unsafe` blocks.

### Memory-Unsafe Languages (C, C++)

Focus on: **All 25 CWEs**. Memory safety bugs (#5, #7, #8, #11, #13, #14, #16) are critical and require dedicated mitigation through safe functions, smart pointers, compiler flags, and memory sanitizers.

### Recommended compiler flags (C/C++)

```bash
# GCC/Clang hardening flags
-Wall -Wextra -Werror
-fstack-protector-strong
-D_FORTIFY_SOURCE=2
-fPIE -pie
-Wformat=2 -Wformat-security
-fsanitize=address,undefined  # For testing (not production)
```

---

## References

- [CWE Top 25:2025 — Official List](https://cwe.mitre.org/top25/archive/2025/2025_cwe_top25.html)
- [CWE Top 25:2025 — Key Insights](https://cwe.mitre.org/top25/archive/2025/2025_key_insights.html)
- [CWE Top 25:2025 — Methodology](https://cwe.mitre.org/top25/archive/2025/2025_methodology.html)
- [CISA: 2025 CWE Top 25 Announcement](https://www.cisa.gov/news-events/alerts/2025/12/11/2025-cwe-top-25-most-dangerous-software-weaknesses)
- [CWE Full Database](https://cwe.mitre.org/data/index.html)
- [SANS Top 25 Programming Errors](https://www.sans.org/top25-software-errors)

---

## License

This file is released under [CC BY-SA 4.0](https://creativecommons.org/licenses/by-sa/4.0/). Based on the CWE™ project by [The MITRE Corporation](https://www.mitre.org/). CWE is a trademark of The MITRE Corporation.
