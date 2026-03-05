# 🐍 Python 3 Security Rules

> **Standard:** Python 3.x Language & Standard Library Security
> **Sources:** Python Security Advisories (python-security.readthedocs.io), NIST NVD, CVE Details, OWASP, Bandit Rules, CWE Top 25
> **Version:** 1.0.0
> **Last updated:** March 2026
> **Scope:** Python 3.x language, standard library only — no framework-specific rules

---

## General Instructions

Apply these rules to all Python 3 code. Many vulnerabilities in Python arise from misuse of standard library modules, unsafe defaults, or language-specific behaviors. Follow the mandatory rules and use the ✅/❌ examples as references for secure vs insecure patterns.

---

## 1. Deserialization — pickle, marshal, shelve

**Vulnerability:** pickle/marshal/shelve execute arbitrary Python code during deserialization via `__reduce__`, `__getstate__` and related dunder methods. There is no safe way to deserialize untrusted pickle data.

**References:** CWE-502, CVE-2022-42919 (multiprocessing privilege escalation via pickle)

### Mandatory Rules

- **Never deserialize pickle, marshal, or shelve data from untrusted sources** — network, user input, uploaded files, databases fed by external parties.
- Use **JSON, msgpack, or protobuf** for data interchange with external systems.
- If pickle is absolutely required internally, **sign the payload** with HMAC-SHA256 and verify before deserializing.
- Never use `multiprocessing` with untrusted processes using the default `fork` context — it serializes via pickle.

```python
# ❌ INSECURE — arbitrary code execution
import pickle
data = request.body  # User-controlled bytes
obj = pickle.loads(data)  # RCE if data is malicious

# ❌ INSECURE — shelve backed by pickle
import shelve
db = shelve.open("userdata")
db["key"] = user_object  # Stored as pickle; RCE on load

# ✅ SECURE — use JSON for untrusted data
import json
data = json.loads(request.body)  # No code execution

# ✅ SECURE — sign + verify if pickle required internally
import pickle, hmac, hashlib

SECRET_KEY = b"..."  # From secrets manager

def safe_serialize(obj: object) -> bytes:
    payload = pickle.dumps(obj)
    sig = hmac.new(SECRET_KEY, payload, hashlib.sha256).digest()
    return sig + payload

def safe_deserialize(data: bytes) -> object:
    sig, payload = data[:32], data[32:]
    expected = hmac.new(SECRET_KEY, payload, hashlib.sha256).digest()
    if not hmac.compare_digest(sig, expected):
        raise ValueError("Invalid signature — deserialization rejected")
    return pickle.loads(payload)
```

---

## 2. Code Execution — eval, exec, compile, __import__

**Vulnerability:** `eval()` and `exec()` execute arbitrary Python. Blocklists (e.g., blocking `import`) are bypassable via `__builtins__`, attribute chaining, and encoding tricks.

**References:** CWE-78, CWE-94, Bandit B307

### Mandatory Rules

- **Never call `eval()` or `exec()` with any data derived from user input**, environment variables, file contents, or network data.
- Use `ast.literal_eval()` to safely parse Python literals (str, int, float, list, dict, tuple, bool, None, bytes).
- **Never implement a blocklist** as a substitute for avoiding eval — it is always bypassable.
- Do not use `compile()` with untrusted source strings.
- Do not pass user-controlled strings to `__import__()` or `importlib.import_module()`.

```python
# ❌ INSECURE — eval with user input
user_expr = request.args["formula"]
result = eval(user_expr)  # RCE: user passes __import__('os').system('ls')

# ❌ INSECURE — blocklist bypass
blocklist = ["import", "os", "sys"]
if not any(word in user_expr for word in blocklist):
    eval(user_expr)  # Bypassed with: getattr(__builtins__,'__import__')('os')

# ❌ INSECURE — dynamic import with user input
module_name = request.args["module"]
mod = __import__(module_name)  # Loads any installed module

# ✅ SECURE — ast.literal_eval for data parsing
import ast
raw = request.args["data"]  # e.g., "{'key': 42}"
try:
    data = ast.literal_eval(raw)  # Only literals — no function calls
    if not isinstance(data, dict):
        raise ValueError("Expected dict")
except (ValueError, SyntaxError) as e:
    raise BadRequest(f"Invalid data: {e}")

# ✅ SECURE — explicit allowlist for dynamic dispatch
ALLOWED_MODULES = {"math", "statistics"}
module_name = request.args["module"]
if module_name not in ALLOWED_MODULES:
    raise BadRequest("Module not allowed")
mod = importlib.import_module(module_name)
```

---

## 3. Subprocess & OS Command Injection

**Vulnerability:** `shell=True` passes the command string to the shell (`/bin/sh -c`), enabling injection via metacharacters (`;`, `|`, `$()`, etc.). `os.system()` and `os.popen()` always invoke the shell.

**References:** CWE-78, Bandit B602/B603/B605, OWASP A03:2021

### Mandatory Rules

- **Always pass a list of arguments** to `subprocess.run()`, `subprocess.Popen()`, etc. Never use `shell=True` with user-controlled data.
- **Never use `os.system()`, `os.popen()`, or `commands`** — replace with `subprocess.run()`.
- If `shell=True` is unavoidable (rare), use `shlex.quote()` on every argument separately.
- Set `timeout=` on all subprocess calls to prevent hanging.
- Capture and validate output — do not pass subprocess output back to another shell call.

```python
import subprocess, shlex

# ❌ INSECURE — shell=True with user input
filename = request.args["file"]
subprocess.run(f"cat {filename}", shell=True)  # filename = "x; rm -rf /"

# ❌ INSECURE — os.system
import os
os.system(f"convert {user_file} output.png")  # Shell injection

# ✅ SECURE — list of arguments, no shell
filename = request.args["file"]
result = subprocess.run(
    ["cat", filename],       # List: no shell parsing
    capture_output=True,
    text=True,
    timeout=10,              # Prevent hanging
    check=True,              # Raise on non-zero exit
)

# ✅ SECURE — if shell=True is truly required
safe_arg = shlex.quote(user_input)  # Wraps in single quotes, escapes internals
subprocess.run(f"convert {safe_arg} output.png", shell=True, timeout=10)
```

---

## 4. XML Processing — XXE, Billion Laughs

**Vulnerability:** Python's built-in XML parsers (xml.etree, xml.minidom, xml.sax, xml.dom) are vulnerable to XML External Entity (XXE) injection and Billion Laughs (exponential entity expansion) by default.

**References:** CVE-2024-45490/45491/45492 (libexpat integer overflows), CVE-2013-0340 (Billion Laughs), OWASP A05:2021

### Mandatory Rules

- **Use `defusedxml`** for all XML parsing of untrusted input — it disables external entities, DTD processing, and entity expansion by default.
- Never use `xml.etree.ElementTree`, `xml.minidom`, `xml.sax`, or `xml.dom` directly on untrusted XML.
- If `defusedxml` is not available, configure the parser to forbid external entities explicitly.
- Limit XML document size before parsing (reject payloads > configured max bytes).
- Keep Python's bundled `libexpat` up to date — patch for CVE-2024-45490/45491/45492 is in Python 3.8.20+.

```python
# ❌ INSECURE — XXE: reads /etc/passwd via external entity
import xml.etree.ElementTree as ET
xml_data = b"""<?xml version="1.0"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<root>&xxe;</root>"""
tree = ET.fromstring(xml_data)  # Returns file contents on some parsers

# ❌ INSECURE — Billion Laughs: exponential memory expansion
xml_bomb = b"""<?xml version="1.0"?>
<!DOCTYPE lol [
  <!ENTITY lol "lol">
  <!ENTITY lol2 "&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;">
  <!ENTITY lol3 "&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;">
]>
<root>&lol3;</root>"""  # Expands to gigabytes

# ✅ SECURE — defusedxml blocks both attacks
import defusedxml.ElementTree as ET

MAX_XML_BYTES = 1_048_576  # 1 MB

def parse_xml(raw: bytes) -> ET.Element:
    if len(raw) > MAX_XML_BYTES:
        raise ValueError("XML payload too large")
    return ET.fromstring(raw)  # defusedxml raises on XXE and Billion Laughs

# ✅ SECURE — manual restriction (fallback without defusedxml)
from xml.etree.ElementTree import XMLParser

class SafeParser(XMLParser):
    def __init__(self):
        super().__init__()
        self.parser.UseForeignDTD(False)  # Disable DTD
        self.parser.SetParamEntityParsing(0)  # Disable param entities
```

---

## 5. Cryptography — Hashing, Randomness, TLS

**Vulnerability:** MD5 and SHA-1 are broken for cryptographic use. Python's `random` module uses Mersenne Twister (non-CSPRNG). Insecure SSL contexts allow MITM.

**References:** CVE-2022-48566 (hmac timing bug), CWE-326/327/330, NIST SP 800-57

### Mandatory Rules

- **Never use MD5 or SHA-1** for security purposes (signatures, fingerprints, password storage, HMAC).
- **Never use `random` module** for security-sensitive values — use `secrets` exclusively.
- **Never compare secrets with `==`** — use `hmac.compare_digest()` to prevent timing attacks.
- Use **Argon2id** (or bcrypt/scrypt) for password hashing — never raw SHA-256 or PBKDF2 alone.
- Use **AES-256-GCM** for symmetric encryption via `cryptography` library — never roll custom crypto.
- Create SSL contexts with `ssl.create_default_context()` — never set `verify_mode = ssl.CERT_NONE`.
- Generate IVs and nonces with `secrets.token_bytes()` or `os.urandom()` — never reuse.
- Enforce **TLS 1.2+ minimum** — disable SSLv3/TLS 1.0/1.1 explicitly.

```python
import secrets, hmac, hashlib
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import ssl

# ❌ INSECURE — broken hash algorithms
import hashlib
token_hash = hashlib.md5(token.encode()).hexdigest()  # Broken: collisions known
pw_hash = hashlib.sha1(password.encode()).hexdigest()  # Broken + fast = crackable

# ❌ INSECURE — non-CSPRNG for tokens
import random
session_token = str(random.randint(1000000, 9999999))  # Predictable state

# ❌ INSECURE — timing-vulnerable comparison
if provided_token == stored_token:  # Timing attack reveals token length/content
    return True

# ❌ INSECURE — disabled certificate verification
context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
context.verify_mode = ssl.CERT_NONE  # MITM possible

# ✅ SECURE — CSPRNG tokens
session_token = secrets.token_urlsafe(32)  # 256 bits entropy
api_key = secrets.token_hex(32)

# ✅ SECURE — constant-time comparison
if hmac.compare_digest(
    provided_token.encode(),
    stored_token.encode()
):
    return True

# ✅ SECURE — AES-256-GCM encryption
key = secrets.token_bytes(32)  # 256-bit key, store in secrets manager
aesgcm = AESGCM(key)
nonce = secrets.token_bytes(12)  # 96-bit nonce, unique per encryption
ciphertext = aesgcm.encrypt(nonce, plaintext, associated_data)

# ✅ SECURE — SSL with defaults
context = ssl.create_default_context()  # TLS 1.2+, valid certs, hostname check
context.minimum_version = ssl.TLSVersion.TLSv1_2

# ✅ SECURE — password hashing with Argon2id
from argon2 import PasswordHasher
ph = PasswordHasher(time_cost=2, memory_cost=65536, parallelism=2)
hashed = ph.hash(password)
ph.verify(hashed, provided_password)  # Raises on failure
```

---

## 6. Path Traversal & File Operations

**Vulnerability:** User-controlled paths can traverse outside intended directories. `tempfile.mktemp()` has a TOCTOU race condition. `tarfile.extractall()` allows path traversal by default.

**References:** CVE-2007-4559 (tarfile path traversal), CWE-22, CWE-377

### Mandatory Rules

- **Resolve and validate all user-supplied paths** with `Path.resolve()` and `Path.is_relative_to()` before any file operation.
- **Never use `tempfile.mktemp()`** — use `tempfile.NamedTemporaryFile()` or `tempfile.mkstemp()`.
- **Never call `tarfile.extractall()` without validating members** — check for `..` and absolute paths.
- **Rename uploaded files server-side** with a UUID — never use user-supplied filenames.
- Validate file types by **magic bytes** (content inspection), not by extension or Content-Type header.
- Store uploads outside the web root.

```python
from pathlib import Path
import tempfile, tarfile, uuid, mimetypes

BASE_DIR = Path("/app/uploads").resolve()

# ❌ INSECURE — path traversal
def read_file(filename: str) -> str:
    path = Path("/app/uploads") / filename  # filename = "../../etc/passwd"
    return path.read_text()  # Reads /etc/passwd

# ❌ INSECURE — race condition in temp file
name = tempfile.mktemp()  # Returns name, does not create
with open(name, "w") as f:  # Another process can create this file first
    f.write(data)

# ❌ INSECURE — tarfile path traversal
with tarfile.open("upload.tar") as t:
    t.extractall("/app/uploads")  # Members can write to /app/../../etc/cron.d

# ✅ SECURE — path validation
def read_file(filename: str) -> str:
    requested = (BASE_DIR / filename).resolve()
    if not requested.is_relative_to(BASE_DIR):
        raise PermissionError(f"Path traversal detected: {filename}")
    return requested.read_text()

# ✅ SECURE — atomic temp file creation
def write_temp(data: bytes) -> Path:
    fd, path = tempfile.mkstemp(dir="/tmp/secure")
    try:
        with open(fd, "wb") as f:
            f.write(data)
    except Exception:
        Path(path).unlink(missing_ok=True)
        raise
    return Path(path)

# ✅ SECURE — tarfile with member validation
def safe_extract(tar_path: str, dest: str) -> None:
    dest_path = Path(dest).resolve()
    with tarfile.open(tar_path) as t:
        for member in t.getmembers():
            member_path = (dest_path / member.name).resolve()
            if not member_path.is_relative_to(dest_path):
                raise ValueError(f"Path traversal in archive: {member.name}")
        t.extractall(dest_path)

# ✅ SECURE — UUID rename + magic byte validation
ALLOWED_MAGIC = {
    b"\xff\xd8\xff": "image/jpeg",
    b"\x89PNG\r\n": "image/png",
    b"%PDF": "application/pdf",
}

def save_upload(file_bytes: bytes, original_name: str) -> Path:
    header = file_bytes[:6]
    if not any(header.startswith(magic) for magic in ALLOWED_MAGIC):
        raise ValueError("File type not allowed")
    ext = Path(original_name).suffix.lower()
    safe_name = f"{uuid.uuid4()}{ext}"  # UUID, never user name
    dest = BASE_DIR / safe_name
    dest.write_bytes(file_bytes)
    return dest
```

---

## 7. Regular Expression — ReDoS

**Vulnerability:** Nested quantifiers and alternation with overlap cause catastrophic backtracking, halting the process under attacker-controlled input.

**References:** CVE-2019-20907 (tarfile ReDoS), CWE-400, OWASP DOS via ReDoS

### Mandatory Rules

- **Avoid nested quantifiers** (`(a+)+`, `(a|aa)+`, `(a*)*`) on patterns matching untrusted input.
- **Set a maximum input length** before applying regex to user data.
- Use **`re2`** (Google's RE2 library) for patterns that must match untrusted input — it guarantees linear time.
- Apply **`signal.alarm`** timeout (Unix) or run regex in a thread with `concurrent.futures.ThreadPoolExecutor` with a timeout for patterns you cannot rewrite.
- Test patterns with tools like `regexploit` or `vulture` before deploying.

```python
import re
from concurrent.futures import ThreadPoolExecutor, TimeoutError as FutureTimeout

# ❌ INSECURE — catastrophic backtracking
pattern = re.compile(r"(a+)+b")
re.match(pattern, "a" * 40)  # Exponential: tries 2^40 paths

# ❌ INSECURE — email validation with overlapping alternation
email_pattern = re.compile(r"^([a-zA-Z0-9]([a-zA-Z0-9\-]*[a-zA-Z0-9])?\.)+[a-zA-Z]+$")
# Input "aaaaaaaaaaaaaaaa@" causes backtracking explosion

# ✅ SECURE — limit input length before regex
MAX_INPUT = 200

def validate_input(pattern: re.Pattern, text: str) -> bool:
    if len(text) > MAX_INPUT:
        raise ValueError(f"Input exceeds {MAX_INPUT} chars")
    return bool(pattern.match(text))

# ✅ SECURE — timeout via thread
REGEX_TIMEOUT = 1.0  # seconds

def safe_match(pattern: re.Pattern, text: str) -> bool:
    if len(text) > MAX_INPUT:
        return False
    with ThreadPoolExecutor(max_workers=1) as executor:
        future = executor.submit(pattern.match, text)
        try:
            result = future.result(timeout=REGEX_TIMEOUT)
            return bool(result)
        except FutureTimeout:
            future.cancel()
            raise ValueError("Regex timeout — possible ReDoS")

# ✅ SECURE — use re2 for untrusted input
try:
    import re2  # google-re2 package
    safe_pattern = re2.compile(r"[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}")
except ImportError:
    # Fallback: simple pattern with length guard
    safe_pattern = re.compile(r"[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}")
```

---

## 8. Injection — Logging, Format Strings, SQL

**Vulnerability:** User data injected into log messages enables log forging. Format strings with `%` or `.format()` on user input enable attribute disclosure. SQL injection via f-strings.

**References:** CWE-117 (Log Injection), CWE-89 (SQL), CWE-134 (Format String), CVE-2024-6923 (email header injection)

### Mandatory Rules

- **Pass user data as logging arguments**, not via f-string interpolation — prevents format string attacks and log injection.
- **Sanitize newlines** (`\r`, `\n`) in any user data written to logs.
- **Never build SQL strings** with f-strings or `%` formatting — always use parameterized queries.
- **Never use `.format()` or f-strings with user-controlled format strings**.
- When writing to email headers or HTTP headers, validate for CRLF injection.

```python
import logging, re

logger = logging.getLogger(__name__)

# ❌ INSECURE — log forging via CRLF injection
username = "alice\nINFO:app:Logged in: admin"
logger.info(f"Login attempt: {username}")  # Creates fake log line

# ❌ INSECURE — format string attribute disclosure
template = request.args["template"]  # "{obj.__class__.__bases__}"
result = template.format(obj=some_object)  # Exposes internal attributes

# ❌ INSECURE — SQL injection via f-string
name = request.args["name"]  # "' OR '1'='1"
cursor.execute(f"SELECT * FROM users WHERE name = '{name}'")  # Injection

# ✅ SECURE — logging with separate argument (no f-string)
def sanitize_log(value: str) -> str:
    return re.sub(r"[\r\n]", " ", str(value))

logger.info("Login attempt: %s", sanitize_log(username))  # % args, not f-string

# ✅ SECURE — parameterized SQL
cursor.execute("SELECT * FROM users WHERE name = ?", (name,))      # SQLite
cursor.execute("SELECT * FROM users WHERE name = %s", (name,))     # psycopg2

# ✅ SECURE — ORM with parameterized queries
User.objects.filter(name=name)          # Django ORM — safe
session.query(User).filter_by(name=name)  # SQLAlchemy — safe

# ❌ INSECURE — ORM raw with injection
User.objects.raw(f"SELECT * FROM users WHERE name = '{name}'")  # Injection
```

---

## 9. Network — urllib, socket, SSL

**Vulnerability:** `urllib.parse` URL validation is bypassable (CVE-2023-24329). Default socket bindings may be too permissive. SSL context misconfigurations allow MITM.

**References:** CVE-2023-24329 (urllib bypass), CVE-2021-3426 (pydoc SSRF), CVE-2022-45061 (IDNA DoS)

### Mandatory Rules

- **Validate URLs with an allowlist** of schemes and a blocklist of private/internal IP ranges — `urllib.parse.urlparse()` alone is not enough (CVE-2023-24329: leading whitespace bypasses scheme check).
- **Never expose `http.server` or `pydoc -p` on non-loopback interfaces** in production.
- **Limit hostname length** before passing to `encodings.idna` to prevent DoS (CVE-2022-45061: > 100 chars can trigger quadratic complexity).
- Always set `socket.setdefaulttimeout()` or per-socket timeouts.
- Use `ssl.create_default_context()` — never create bare `ssl.SSLContext` without setting `check_hostname = True` and `verify_mode = ssl.CERT_REQUIRED`.

```python
import urllib.parse, socket, ssl, ipaddress

ALLOWED_SCHEMES = {"https"}
BLOCKED_CIDRS = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("169.254.0.0/16"),  # Link-local
    ipaddress.ip_network("::1/128"),
]

# ❌ INSECURE — CVE-2023-24329: whitespace bypass
url = "  file:///etc/passwd"
parsed = urllib.parse.urlparse(url)
if parsed.scheme not in ALLOWED_SCHEMES:  # parsed.scheme == "" — bypassed!
    raise ValueError("Invalid scheme")

# ✅ SECURE — strip + validate + IP check
def validate_url(url: str) -> str:
    url = url.strip()  # Strip whitespace FIRST (CVE-2023-24329)
    parsed = urllib.parse.urlparse(url)
    if parsed.scheme not in ALLOWED_SCHEMES:
        raise ValueError(f"Scheme not allowed: {parsed.scheme}")
    hostname = parsed.hostname or ""
    if len(hostname) > 253:  # CVE-2022-45061: limit IDNA decoding length
        raise ValueError("Hostname too long")
    try:
        ip = ipaddress.ip_address(hostname)
        if any(ip in cidr for cidr in BLOCKED_CIDRS):
            raise ValueError("Internal IP not allowed (SSRF prevention)")
    except ValueError as e:
        if "Internal IP" in str(e):
            raise
        pass  # Not an IP address — DNS name, further validation needed
    return url

# ✅ SECURE — SSL context
context = ssl.create_default_context()
context.minimum_version = ssl.TLSVersion.TLSv1_2
# check_hostname and CERT_REQUIRED are set by default

# ✅ SECURE — socket timeout
socket.setdefaulttimeout(10)
```

---

## 10. Language Risks — assert, sys.path, PYTHONPATH, GIL

**Vulnerability:** `assert` is removed by `python -O`. `sys.path` pollution allows import hijacking. GIL does not protect application-level shared state.

**References:** CWE-617 (assert in non-debug code), Python Advisory PSF-2023-9 (sys.path injection)

### Mandatory Rules

- **Never use `assert` for input validation or security checks** — it is stripped by `python -O`. Use `if`/`raise` instead.
- **Never append untrusted paths to `sys.path`** — attackers who control files in that path can inject arbitrary modules.
- Run Python scripts with **`-I` (isolated mode)** in production to ignore `PYTHONPATH`, `PYTHONSTARTUP`, and user site-packages.
- Protect shared mutable state in multi-threaded code with `threading.Lock()` — the GIL does not prevent data races at the application level.
- **Verify `.pyc` hash integrity** — enable `PyConfig.check_hash_pycs_mode = "checked_hash"` to prevent bytecode tampering.
- Do not trust `.pth` files or `sitecustomize.py` in site-packages from untrusted packages.

```python
import threading

# ❌ INSECURE — assert for validation (stripped with python -O)
def withdraw(account, amount):
    assert amount > 0, "Amount must be positive"  # Removed by -O!
    assert account.balance >= amount  # Removed by -O!
    account.balance -= amount  # Negative balance possible

# ❌ INSECURE — sys.path from user input
import sys
plugin_dir = request.args["plugin_dir"]  # Attacker controls /tmp
sys.path.insert(0, plugin_dir)
import user_plugin  # Loads /tmp/user_plugin.py — attacker-controlled

# ❌ INSECURE — GIL false safety (data race)
counter = 0

def increment():
    global counter
    for _ in range(100_000):
        counter += 1  # LOAD, ADD, STORE — not atomic despite GIL

# ✅ SECURE — if/raise instead of assert
def withdraw(account, amount: int) -> None:
    if amount <= 0:
        raise ValueError(f"Amount must be positive, got {amount}")
    if account.balance < amount:
        raise InsufficientFunds("Insufficient balance")
    account.balance -= amount

# ✅ SECURE — locked counter
lock = threading.Lock()
counter = 0

def safe_increment():
    global counter
    with lock:
        counter += 1  # Atomic under lock

# ✅ SECURE — fixed sys.path allowlist
ALLOWED_PLUGIN_DIRS = {"/app/plugins", "/opt/company/plugins"}

def load_plugin(plugin_dir: str) -> None:
    resolved = Path(plugin_dir).resolve()
    if str(resolved) not in ALLOWED_PLUGIN_DIRS:
        raise PermissionError("Plugin dir not in allowlist")
    sys.path.insert(0, str(resolved))
```

---

## 11. Supply Chain & Dependencies

**Vulnerability:** Unpinned or unverified dependencies enable supply chain attacks. Malicious packages use typosquatting, dependency confusion, and post-install scripts.

**References:** CWE-829, OWASP A08:2021, NIST SSDF Supply Chain Risk

### Mandatory Rules

- **Pin all dependencies** to exact versions (`==`) in `requirements.txt` — never use `>=`, `~=`, or `*`.
- **Include SHA-256 hashes** in requirements and install with `pip install --require-hashes`.
- **Scan dependencies** with `pip-audit` or `safety` in every CI run — fail the build on CRITICAL/HIGH CVEs.
- **Audit new packages** before adding — check author, download count, source code, and install hooks.
- **Never install packages as root** — always install in a virtualenv.
- Use a **private mirror** (Artifactory, Nexus) to proxy PyPI and block unexpected packages.
- Claim internal package names in PyPI to prevent **dependency confusion** attacks.

```toml
# ❌ INSECURE — unpinned versions
# requirements.txt:
# Flask>=1.0
# requests~=2.28

# ✅ SECURE — pinned with hashes
# requirements.txt:
# Flask==3.0.3 \
#   --hash=sha256:34374... \
#   --hash=sha256:a5c3e...
# requests==2.31.0 \
#   --hash=sha256:58cd2...
```

```bash
# ✅ SECURE — generate locked requirements with hashes
pip-compile --generate-hashes requirements.in

# ✅ SECURE — audit for vulnerabilities
pip-audit                          # Checks installed packages
pip-audit -r requirements.txt      # Checks requirements file

# ✅ SECURE — install with hash verification
pip install --require-hashes -r requirements.txt

# ✅ SECURE — static analysis
bandit -r src/ -ll                 # Level: LOW+ issues
semgrep --config=p/python src/     # Pattern-based analysis
```

---

## 12. Sensitive Data — Secrets, Logging, Memory

**Vulnerability:** Hardcoded credentials, secrets in environment variables, and logged secrets are common attack vectors.

**References:** CWE-312/313/532, OWASP A02:2021

### Mandatory Rules

- **Never hardcode secrets** (passwords, API keys, tokens) in source code, even in tests.
- Read secrets from **secrets managers** (HashiCorp Vault, AWS Secrets Manager, GCP Secret Manager) — not from `os.environ` in plaintext.
- **Never log secrets** — sanitize sensitive fields before passing to `logger.*`.
- **Clear secrets from memory** when no longer needed (`bytearray` instead of `str`, explicit overwrite).
- Run **`detect-secrets`** or `gitleaks` in pre-commit hooks.

```python
import os, logging

logger = logging.getLogger(__name__)

# ❌ INSECURE — hardcoded credentials
DB_PASSWORD = "hunter2"  # In source code = in git history forever

# ❌ INSECURE — secrets in logs
api_key = get_secret("api_key")
logger.info(f"Using API key: {api_key}")  # Leaked to log aggregation

# ❌ INSECURE — raw env var (still in memory, logged by debug tools)
password = os.environ["DB_PASSWORD"]  # Visible in /proc/environ

# ✅ SECURE — secrets manager integration
import boto3
from botocore.exceptions import ClientError

def get_secret(secret_name: str) -> str:
    client = boto3.client("secretsmanager", region_name="us-east-1")
    try:
        response = client.get_secret_value(SecretId=secret_name)
        return response["SecretString"]
    except ClientError as e:
        raise RuntimeError(f"Failed to fetch secret: {e}") from e

db_password = get_secret("prod/db/password")

# ✅ SECURE — redacted logging
class RedactedRecord(logging.LogRecord):
    SENSITIVE = {"password", "token", "secret", "api_key", "auth"}
    def getMessage(self) -> str:
        msg = super().getMessage()
        for keyword in self.SENSITIVE:
            if keyword in msg.lower():
                return "[REDACTED — contains sensitive field]"
        return msg

# ✅ SECURE — mutable bytes for secrets (can be zeroed)
password_bytes = bytearray(get_secret("password").encode())
# ... use password_bytes ...
for i in range(len(password_bytes)):
    password_bytes[i] = 0  # Overwrite
```

---

## Quick Security Checklist

| Category | Check | Compliant |
|----------|-------|-----------|
| Deserialization | No `pickle.loads()` with untrusted data | ☐ |
| Deserialization | No `marshal`, `shelve` with untrusted data | ☐ |
| Code Execution | No `eval()`/`exec()` with user input | ☐ |
| Code Execution | `ast.literal_eval()` used for config parsing | ☐ |
| Subprocess | `shell=False` (default) on all subprocess calls | ☐ |
| Subprocess | Arguments passed as list, not string | ☐ |
| XML | `defusedxml` used for all XML parsing | ☐ |
| Cryptography | No MD5/SHA-1 for security purposes | ☐ |
| Cryptography | `secrets` module for all tokens/keys | ☐ |
| Cryptography | `hmac.compare_digest()` for secret comparison | ☐ |
| Cryptography | `ssl.create_default_context()` for TLS | ☐ |
| Cryptography | Argon2id/bcrypt for password hashing | ☐ |
| File Operations | `pathlib.resolve()` + `is_relative_to()` for paths | ☐ |
| File Operations | `tempfile.NamedTemporaryFile()` not `mktemp()` | ☐ |
| File Operations | `tarfile` members validated before extraction | ☐ |
| ReDoS | No nested quantifiers on untrusted input | ☐ |
| ReDoS | Input length limit before regex | ☐ |
| Logging | Log arguments via `%s`, not f-string | ☐ |
| Logging | CRLF stripped from user data in logs | ☐ |
| SQL | Parameterized queries everywhere | ☐ |
| Network | URL scheme + IP validated (SSRF prevention) | ☐ |
| Network | Hostname length limited (< 253 chars) | ☐ |
| Language | No `assert` for security/validation checks | ☐ |
| Language | No `sys.path` modification with untrusted paths | ☐ |
| Language | Shared state protected with `threading.Lock()` | ☐ |
| Dependencies | All packages pinned with `==` and SHA-256 hashes | ☐ |
| Dependencies | `pip-audit` running in CI | ☐ |
| Dependencies | `bandit -r` running in CI | ☐ |
| Secrets | No hardcoded secrets in source code | ☐ |
| Secrets | Secrets from secrets manager, not env vars | ☐ |
| Secrets | No secrets in log output | ☐ |

---

## Tooling Reference

| Tool | Purpose | Command |
|------|---------|---------|
| `bandit` | Static analysis — common Python security issues | `bandit -r src/ -ll` |
| `semgrep` | Advanced pattern-based analysis | `semgrep --config=p/python src/` |
| `pip-audit` | Dependency CVE scanning | `pip-audit -r requirements.txt` |
| `safety` | Dependency vulnerability database check | `safety check` |
| `detect-secrets` | Pre-commit secret scanning | `detect-secrets scan` |
| `gitleaks` | Git history secret scanning | `gitleaks detect` |
| `mypy` | Type checking (catches type confusion bugs) | `mypy src/` |
| `defusedxml` | Drop-in XML parser with security defaults | `pip install defusedxml` |
| `argon2-cffi` | Argon2id password hashing | `pip install argon2-cffi` |
| `cryptography` | AES-GCM, RSA, ECDSA | `pip install cryptography` |
| `google-re2` | Linear-time regex (RE2 engine) | `pip install google-re2` |

---

## CVE Quick Reference

| CVE | Module | Type | Fixed In |
|-----|--------|------|----------|
| CVE-2023-24329 | `urllib.parse` | SSRF URL bypass via whitespace | 3.7.17, 3.8.17, 3.9.17, 3.10.12, 3.11.4 |
| CVE-2023-27043 | `email.utils` | Email address parsing bypass | 3.11.3+ |
| CVE-2024-6923 | `email` | CRLF header injection | 3.8.20, 3.9.20, 3.10.15, 3.11.10, 3.12.5 |
| CVE-2024-7592 | `http.cookies` | DoS — quadratic backslash parsing | 3.8.20, 3.9.20, 3.12.5 |
| CVE-2022-45061 | `encodings.idna` | DoS — quadratic IDNA decoding | 3.7.16, 3.8.16, 3.9.16, 3.10.9, 3.11.1 |
| CVE-2019-20907 | `tarfile` | ReDoS in pax header parsing | 3.8.4 |
| CVE-2021-3426 | `pydoc` | SSRF — arbitrary file read via HTTP | 3.8.9, 3.9.3 |
| CVE-2021-3177 | `ctypes` | Buffer overflow in `PyCArg_repr` | 3.7.10, 3.8.8, 3.9.2 |
| CVE-2024-45490 | `xml` (libexpat) | Negative length — parser crash | 3.8.20, 3.9.20, 3.12.6 |
| CVE-2024-45491 | `xml` (libexpat) | Integer overflow in dtdCopy | 3.8.20, 3.9.20, 3.12.6 |
| CVE-2024-45492 | `xml` (libexpat) | Integer overflow in nextScaffoldPart | 3.8.20, 3.9.20, 3.12.6 |
| CVE-2022-42919 | `multiprocessing` | Privilege escalation via pickle | 3.9.16, 3.10.9 |
| CVE-2022-48566 | `hmac` | Timing attack in compare_digest | 3.9.1 |

---

## References

- [Python Security Advisories](https://python-security.readthedocs.io/vulnerabilities.html)
- [Python CVE Database — CVE Details](https://www.cvedetails.com/product/18230/Python-Python.html)
- [NIST NVD — CPE: cpe:2.3:a:python:python](https://nvd.nist.gov/)
- [Bandit — Python Security Linter](https://bandit.readthedocs.io/)
- [OWASP Python Security Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Python_Security_Cheat_Sheet.html)
- [defusedxml — Secure XML Parsing](https://github.com/tiran/defusedxml)
- [PEP 476 — HTTPS Certificate Validation](https://peps.python.org/pep-0476/)
- [Python Docs — secrets module](https://docs.python.org/3/library/secrets.html)
- [Python Docs — ssl module](https://docs.python.org/3/library/ssl.html)
- [Python Docs — subprocess — Security considerations](https://docs.python.org/3/library/subprocess.html#security-considerations)

---

*License: [CC BY-SA 4.0](https://creativecommons.org/licenses/by-sa/4.0/) — Based on Python Security Advisories, NIST NVD, and OWASP documentation.*
