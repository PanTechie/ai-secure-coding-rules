# 🔷 C# / .NET Security Rules

> **Standard:** C# Language & .NET Runtime Security
> **Sources:** Microsoft Security Advisories, NIST NVD, OWASP .NET Security Cheat Sheet, CVE Details, Snyk Advisories, dotnet/runtime Security Issues
> **Version:** 1.0.0
> **Last updated:** March 2026
> **Scope:** C# language, .NET 6+ BCL, ASP.NET Core — no framework-specific ORM rules beyond ADO.NET and EF Core basics

---

## General Instructions

Apply these rules to all C# and .NET code. Many vulnerabilities arise from unsafe defaults in deserialization APIs, raw SQL construction, unrestricted XML parsing, insecure cryptographic choices, and improper TLS handling. Follow the mandatory rules and use the ✅/❌ examples as references for secure vs insecure patterns.

---

## 1. Deserialization — BinaryFormatter, SoapFormatter, NetDataContractSerializer

**Vulnerability:** `BinaryFormatter`, `SoapFormatter`, `LosFormatter`, and `NetDataContractSerializer` execute arbitrary .NET code during deserialization by invoking constructors, property setters, and `ISerializable` callbacks on attacker-controlled types. There is no safe way to deserialize untrusted data with these APIs. `BinaryFormatter` is disabled by default in .NET 9 and throws `NotSupportedException` unless re-enabled via a runtime switch.

**References:** CWE-502, CVE-2022-21969 (Exchange BinaryFormatter RCE), CVE-2021-26701 (.NET Core Text.Encoding BinaryFormatter chain), MS Security Advisory SDL-18464 (BinaryFormatter deprecation)

### Mandatory Rules

- **Never use `BinaryFormatter`, `SoapFormatter`, `LosFormatter`, or `NetDataContractSerializer`** to deserialize data from any untrusted source — network, HTTP body, cookies, files, queues, or databases.
- **Do not re-enable `BinaryFormatter` via AppContext switches** (`System.Runtime.Serialization.EnableUnsafeBinaryFormatterSerialization`) in .NET 5+ — this reverts a deliberate security hardening.
- Use **`System.Text.Json`** or **`Newtonsoft.Json`** (without dangerous `TypeNameHandling`) for data interchange.
- For binary protocols, use **`MessagePack`**, **`Protobuf-net`**, or **`System.Formats.Cbor`** with explicit type contracts.
- If a legacy API forces `BinaryFormatter`, sandbox the process and treat any deserialized object graph as untrusted.

```csharp
// ❌ INSECURE — arbitrary type graph execution, RCE via gadget chains
var formatter = new BinaryFormatter();
var obj = formatter.Deserialize(stream); // RCE if stream is attacker-controlled

// ❌ INSECURE — SoapFormatter equally dangerous
var soap = new SoapFormatter();
var obj2 = soap.Deserialize(stream);

// ✅ SECURE — use System.Text.Json with explicit model and depth limit
var options = new JsonSerializerOptions {
    PropertyNameCaseInsensitive = true,
    MaxDepth = 32  // Default is 64; CVE-2024-43485: no limit = StackOverflow
};
var dto = JsonSerializer.Deserialize<OrderDto>(stream, options);

// ✅ SECURE — MessagePack with explicit contract (no polymorphism)
var order = MessagePackSerializer.Deserialize<OrderDto>(buffer);
```

### 1.2 Newtonsoft.Json TypeNameHandling

**Vulnerability:** `TypeNameHandling.All` (or `Auto`/`Objects`/`Arrays`) causes Newtonsoft.Json to read the `$type` property from JSON and instantiate any .NET type present in the runtime. Attackers craft payloads that invoke RCE gadget chains through types like `System.Windows.Data.ObjectDataProvider` or `System.Web.UI.ObjectStateFormatter`.

**References:** CWE-502, CVE-2019-20564 (Newtonsoft.Json gadget chain), ysoserial.net payloads for TypeNameHandling bypass

#### Mandatory Rules

- **Never use `TypeNameHandling.All`, `.Auto`, `.Objects`, or `.Arrays`** with untrusted input — this is equivalent to `BinaryFormatter` in exploitability.
- If `TypeNameHandling` is required for internal systems, supply a **custom `SerializationBinder`** that whitelists a strict set of known safe types; reject all others.
- Default to **`TypeNameHandling.None`** (the default) for all external-facing deserialization.

```csharp
// ❌ INSECURE — attacker controls $type → RCE
var settings = new JsonSerializerSettings {
    TypeNameHandling = TypeNameHandling.All
};
var obj = JsonConvert.DeserializeObject(json, settings);

// ✅ SECURE — explicit model, no type inference from input
var order = JsonConvert.DeserializeObject<OrderDto>(json);

// ✅ SECURE — if polymorphism is needed internally, restrict with a binder
var settings = new JsonSerializerSettings {
    TypeNameHandling = TypeNameHandling.Objects,
    SerializationBinder = new KnownTypesBinder(allowedTypes: [typeof(Cat), typeof(Dog)])
};

public class KnownTypesBinder : ISerializationBinder {
    private readonly HashSet<Type> _allowed;
    public KnownTypesBinder(IEnumerable<Type> allowedTypes) =>
        _allowed = new HashSet<Type>(allowedTypes);

    public Type BindToType(string? assemblyName, string typeName) {
        var type = Type.GetType($"{typeName}, {assemblyName}");
        if (type is null || !_allowed.Contains(type))
            throw new JsonSerializationException($"Type '{typeName}' is not permitted.");
        return type;
    }
    public void BindToName(Type serializedType, out string? assemblyName, out string? typeName) {
        assemblyName = serializedType.Assembly.GetName().Name;
        typeName = serializedType.FullName;
    }
}
```

---

## 2. SQL Injection — ADO.NET and Entity Framework Core

**Vulnerability:** Concatenating user input into SQL strings — in raw ADO.NET `SqlCommand`, Entity Framework Core's `FromSqlRaw`, `ExecuteSqlRaw`, or Dapper's `Execute` — allows an attacker to modify the query structure, bypass authentication, exfiltrate data, or execute stored procedures.

**References:** CWE-89, OWASP SQL Injection, OWASP .NET Security Cheat Sheet

### Mandatory Rules

- **Always use parameterized queries** — `SqlCommand` with `Parameters.AddWithValue`, or `@param` placeholders in EF Core interpolated methods.
- **Prefer `FromSqlInterpolated` over `FromSqlRaw`** in EF Core — it uses `FormattableString` and automatically parameterizes all interpolated values.
- **Never concatenate or `string.Format` user input** into any SQL string, including `ORDER BY`, `LIMIT`, table names, or column names.
- For dynamic column/table names, use an **allowlist** validated against a predefined set of known identifiers.
- Use **EF Core LINQ** for standard queries — the query translator generates parameterized SQL automatically.

```csharp
// ❌ INSECURE — direct string concat → SQLi
string query = "SELECT * FROM Users WHERE Name = '" + username + "'";
var cmd = new SqlCommand(query, conn);

// ❌ INSECURE — FromSqlRaw with interpolation treated as raw string
var users = ctx.Users.FromSqlRaw($"SELECT * FROM Users WHERE Name = '{username}'");

// ✅ SECURE — ADO.NET parameterized
using var cmd = new SqlCommand("SELECT * FROM Users WHERE Name = @name", conn);
cmd.Parameters.AddWithValue("@name", username);

// ✅ SECURE — EF Core interpolated (auto-parameterized)
var users = ctx.Users.FromSqlInterpolated($"SELECT * FROM Users WHERE Name = {username}");

// ✅ SECURE — EF Core LINQ (never generates SQLi)
var users = ctx.Users.Where(u => u.Name == username).ToList();

// ✅ SECURE — dynamic ORDER BY via allowlist
var allowed = new HashSet<string> { "Name", "CreatedAt", "Email" };
if (!allowed.Contains(sortColumn)) throw new ArgumentException("Invalid sort column");
var users = ctx.Users.FromSqlRaw($"SELECT * FROM Users ORDER BY {sortColumn}");
```

---

## 3. XML External Entity (XXE) Injection

**Vulnerability:** .NET's `XmlDocument`, `XPathDocument`, `XslCompiledTransform`, and `XmlReader` can be configured to resolve external entities and DTD definitions. An attacker injects an XML payload with an external entity reference that reads local files (`file:///etc/passwd`), performs SSRF to internal services, or causes denial-of-service (XML bomb / billion laughs).

**References:** CWE-611, CVE-2023-29331 (.NET XXE via XslCompiledTransform), OWASP XXE Prevention Cheat Sheet

### Mandatory Rules

- **Disable DTD processing and external entity resolution** on every XML parser instance by setting `DtdProcessing = DtdProcessing.Prohibit` and `XmlResolver = null`.
- **Use `XmlReader.Create` with secure settings** as the underlying reader for all XML APIs — `XmlDocument`, `XPathDocument`, `XmlSchema`, `XslCompiledTransform`.
- **Never use the default `XmlDocument` constructor with `Load(string)`** on untrusted input without first wrapping it in a secured `XmlReader`.
- Prefer **`System.Text.Json`** or **LINQ to JSON** for data that doesn't require XML.

```csharp
// ❌ INSECURE — default XmlDocument resolves external entities
var doc = new XmlDocument();
doc.Load(userSuppliedXml); // XXE: <!ENTITY xxe SYSTEM "file:///etc/passwd">

// ❌ INSECURE — XmlReaderSettings with DTD processing
var settings = new XmlReaderSettings { DtdProcessing = DtdProcessing.Parse };
using var reader = XmlReader.Create(stream, settings); // XXE/Billion Laughs

// ✅ SECURE — explicit secure settings on every parser
var secureSettings = new XmlReaderSettings {
    DtdProcessing = DtdProcessing.Prohibit,  // Block DTD entirely
    XmlResolver = null,                        // No external resolution
    MaxCharactersFromEntities = 1024           // Prevent entity expansion bombs
};
using var reader = XmlReader.Create(stream, secureSettings);

var doc = new XmlDocument { XmlResolver = null };
doc.Load(reader); // Now safe

// ✅ SECURE — XslCompiledTransform (disable script and document function)
var xslt = new XslCompiledTransform();
var xsltSettings = new XsltSettings(enableDocumentFunction: false, enableScript: false);
xslt.Load("transform.xsl", xsltSettings, new XmlUrlResolver());
```

### 3.2 DataSet and DataTable XML Deserialization

**Vulnerability:** `DataSet.ReadXml()` and `DataTable.ReadXml()` deserialize embedded type information from XML, allowing type instantiation without user consent. CVE-2020-1147 demonstrated RCE via a crafted XML document passed to this API. Even in .NET Core, `DataSet`/`DataTable` accept an `<xs:schema>` with malicious type mappings.

**References:** CWE-502, CVE-2020-1147 (Critical, CVSS 7.8 — DataSet RCE), Microsoft Advisory ADV200011

#### Mandatory Rules

- **Never call `DataSet.ReadXml()` or `DataTable.ReadXml()` on untrusted XML input.**
- Serialize/deserialize structured tabular data with `System.Text.Json` or strongly typed POCOs with EF Core.
- If `DataSet` is required internally, validate and sanitize the XML schema before calling `ReadXml`, and use `XmlReader` with DTD prohibited.

```csharp
// ❌ INSECURE — DataSet.ReadXml() triggers type instantiation from XML
var ds = new DataSet();
ds.ReadXml(userSuppliedStream); // CVE-2020-1147: RCE via malicious <xs:schema>

// ✅ SECURE — use typed POCO deserialization
var records = JsonSerializer.Deserialize<List<OrderRecord>>(jsonStream);
```

---

## 4. Command Injection — Process.Start

**Vulnerability:** Passing user-controlled input to `Process.Start` with `UseShellExecute = true`, or constructing `FileName` / `Arguments` by string concatenation, allows command injection. With `UseShellExecute = true`, the OS shell interprets metacharacters (`&`, `|`, `;`, `` ` ``) enabling arbitrary command execution.

**References:** CWE-78, CWE-88, OWASP OS Command Injection

### Mandatory Rules

- **Set `UseShellExecute = false`** on every `ProcessStartInfo` to bypass the OS shell interpreter.
- **Pass arguments as a structured list** via `ProcessStartInfo.ArgumentList` (available in .NET Core 3.1+) instead of concatenating a single `Arguments` string.
- **Validate command names against an allowlist** — never derive the executable name from user input.
- Prefer **.NET library alternatives** over spawning subprocesses: `System.IO` instead of `cmd /c dir`, `System.IO.Compression` instead of `unzip`, etc.
- If subprocess execution is required, run the child process in a **restricted account** with minimal OS privileges.

```csharp
// ❌ INSECURE — shell interpolation, metachar injection
var psi = new ProcessStartInfo("cmd.exe", $"/c convert {userFile}") {
    UseShellExecute = true
};
Process.Start(psi); // userFile = "file.pdf & del /F /Q C:\\"

// ❌ INSECURE — concatenated Arguments string
var psi2 = new ProcessStartInfo("ffmpeg") {
    Arguments = $"-i {userInput} output.mp4", // Injection via spaces/quotes
    UseShellExecute = false
};

// ✅ SECURE — structured argument list, no shell
var allowedInputs = new HashSet<string> { "audio", "video", "image" };
if (!allowedInputs.Contains(mode)) throw new ArgumentException("Invalid mode");

var psi = new ProcessStartInfo("ffmpeg") {
    UseShellExecute = false,
    RedirectStandardOutput = true,
    RedirectStandardError = true
};
psi.ArgumentList.Add("-i");
psi.ArgumentList.Add(validatedInputPath); // Pre-validated path
psi.ArgumentList.Add(outputPath);
using var proc = Process.Start(psi)!;
await proc.WaitForExitAsync();
```

---

## 5. Cryptography Misuse

**Vulnerability:** Using deprecated algorithms (MD5, SHA-1, DES, 3DES, RC2, RC4), insecure modes (ECB, CBC without MAC), static IVs, short keys, or predictable random number generation breaks the confidentiality and integrity guarantees of cryptographic operations.

**References:** CWE-327, CWE-328, CWE-330, NIST SP 800-57, OWASP Cryptographic Failures

### Mandatory Rules

- **Use `Aes.Create()` with GCM mode** (`AesGcm`) for symmetric encryption — provides both encryption and authentication.
- **Never use `ECB` mode** — it is deterministic and reveals plaintext patterns.
- **Never reuse an IV/nonce** with the same key — generate a fresh cryptographically random IV for every encryption call.
- **Use `RandomNumberGenerator.GetBytes()`** (static, .NET 6+) for all security-sensitive random values — never `System.Random` or `new Random()`.
- **Hash passwords** with `BCrypt.Net-Next`, `Konscious.Security.Cryptography` (Argon2id), or `Microsoft.AspNetCore.Cryptography.KeyDerivation` (PBKDF2) — never with `SHA256.HashData(password)` alone.
- Use **`CryptographicOperations.FixedTimeEquals`** for all secret comparisons — prevents timing attacks.
- **Deprecate `RNGCryptoServiceProvider`** — use the static `RandomNumberGenerator` methods (available .NET 6+).
- **Minimum key sizes:** AES 256-bit, RSA 2048-bit (prefer 3072/4096), ECDSA P-256+.

```csharp
// ❌ INSECURE — MD5 for password storage
byte[] hash = MD5.HashData(Encoding.UTF8.GetBytes(password));

// ❌ INSECURE — AES ECB mode (no IV, deterministic)
using var aes = Aes.Create();
aes.Mode = CipherMode.ECB;

// ❌ INSECURE — static IV (same bytes every time)
byte[] iv = new byte[16]; // All zeros
using var encryptor = aes.CreateEncryptor(key, iv);

// ❌ INSECURE — predictable random (not CSPRNG)
var rand = new Random();
string token = rand.Next(100000, 999999).ToString();

// ✅ SECURE — AES-256-GCM (authenticated encryption)
var key = new byte[32];
RandomNumberGenerator.Fill(key);  // 256-bit key

var nonce = new byte[AesGcm.NonceByteSizes.MaxSize];  // 12 bytes
RandomNumberGenerator.Fill(nonce);

var tag = new byte[AesGcm.TagByteSizes.MaxSize];  // 16 bytes
var ciphertext = new byte[plaintext.Length];

using var aesGcm = new AesGcm(key, AesGcm.TagByteSizes.MaxSize);
aesGcm.Encrypt(nonce, plaintext, ciphertext, tag);
// Store: nonce + tag + ciphertext

// ✅ SECURE — PBKDF2 for password hashing (ASP.NET Core built-in)
string hashed = Convert.ToBase64String(
    KeyDerivation.Pbkdf2(
        password: userPassword,
        salt: RandomNumberGenerator.GetBytes(16),
        prf: KeyDerivationPrf.HMACSHA256,
        iterationCount: 310_000,
        numBytesRequested: 32));

// ✅ SECURE — cryptographically secure random token
string token = Convert.ToHexString(RandomNumberGenerator.GetBytes(32));

// ✅ SECURE — timing-safe comparison
bool match = CryptographicOperations.FixedTimeEquals(
    computedHmac.AsSpan(),
    expectedHmac.AsSpan());
```

---

## 6. Path Traversal

**Vulnerability:** Constructing file paths from user-supplied input without canonicalization allows an attacker to escape the intended directory using `../` sequences, absolute paths, or encoded variants (`%2e%2e%2f`). This leads to unauthorized file reads, writes, or deletions.

**References:** CWE-22, CVE-2021-34473 (Exchange path traversal), OWASP Path Traversal

### Mandatory Rules

- **Canonicalize paths with `Path.GetFullPath()`** and verify the result starts with the expected base directory.
- **Never use `Path.Combine` alone as a security check** — `Path.Combine("/uploads", "/etc/passwd")` returns `/etc/passwd` on Unix (absolute path wins).
- **Validate the file name component** — reject names containing `..`, `/`, `\`, or null bytes before path construction.
- Serve files through a controller/handler that reads and streams the content — never let the framework resolve paths dynamically from user input.
- **Rename uploaded files** to a server-generated UUID (`Guid.NewGuid().ToString("N")`) with a validated extension.

```csharp
// ❌ INSECURE — Path.Combine does not prevent traversal
string filePath = Path.Combine(baseDir, userInput);
// userInput = "../../etc/passwd" → filePath = "/etc/passwd"
return File.ReadAllBytes(filePath);

// ❌ INSECURE — absolute path wins in Path.Combine
Path.Combine("/var/uploads", "/etc/passwd") // Returns "/etc/passwd"

// ✅ SECURE — canonicalize and enforce base directory
string SafeFilePath(string baseDirectory, string userFileName) {
    // Reject obvious traversal characters in the filename component
    if (userFileName.Contains("..") || userFileName.Contains('/') || userFileName.Contains('\\'))
        throw new ArgumentException("Invalid filename");

    string combined = Path.Combine(baseDirectory, userFileName);
    string canonical = Path.GetFullPath(combined);
    string canonicalBase = Path.GetFullPath(baseDirectory)
                           + Path.DirectorySeparatorChar;

    if (!canonical.StartsWith(canonicalBase, StringComparison.OrdinalIgnoreCase))
        throw new UnauthorizedAccessException("Path escapes the allowed directory");

    return canonical;
}

// ✅ SECURE — rename uploaded file to UUID
string safeFileName = Guid.NewGuid().ToString("N") + ".pdf";
string destPath = SafeFilePath(uploadDir, safeFileName);
await using var dest = File.OpenWrite(destPath);
await upload.CopyToAsync(dest);
```

---

## 7. LDAP Injection

**Vulnerability:** Concatenating user input into LDAP search filters or distinguished names allows an attacker to modify the query structure, bypass authentication, or enumerate the directory. LDAP metacharacters include `*`, `(`, `)`, `\`, `NUL`.

**References:** CWE-90, OWASP LDAP Injection Prevention Cheat Sheet

### Mandatory Rules

- **Escape all user-controlled values** placed in LDAP filter strings using a character-by-character allowlist or an encoding library.
- **Never concatenate user input** directly into `DirectorySearcher.Filter` or `DirectoryEntry.Path`.
- Use an allowlist for acceptable input characters (e.g., alphanumeric + `@`, `.`, `-` for a username field).
- Prefer **readonly LDAP service accounts** with minimum required permissions — never bind with a privileged account for search queries.

```csharp
// ❌ INSECURE — LDAP filter injection
string filter = $"(sAMAccountName={username})";
// username = "*)(uid=*))(|(uid=*" bypasses the filter
var searcher = new DirectorySearcher(entry) { Filter = filter };

// ✅ SECURE — allowlist-validate the username before use
static string EscapeLdapFilter(string input) {
    var sb = new StringBuilder();
    foreach (char c in input) {
        sb.Append(c switch {
            '\\' => @"\5c", '*' => @"\2a", '(' => @"\28",
            ')' => @"\29", '\0' => @"\00", '/' => @"\2f",
            _ => c.ToString()
        });
    }
    return sb.ToString();
}

string safeUsername = EscapeLdapFilter(username);
var searcher = new DirectorySearcher(entry) {
    Filter = $"(sAMAccountName={safeUsername})"
};
```

---

## 8. Regex — ReDoS (Regular Expression Denial of Service)

**Vulnerability:** .NET's `Regex` engine uses backtracking by default. Pathological patterns evaluated against attacker-controlled input can trigger catastrophic backtracking (exponential time complexity), causing the application thread to hang for minutes or crash the process.

**References:** CWE-1333, CVE-2019-1147 (.NET ReDoS), OWASP Denial of Service

### Mandatory Rules

- **Set a `Regex` timeout** for every regex applied to user-controlled input — use the overload accepting `TimeSpan`.
- **Use `RegexOptions.NonBacktracking`** (.NET 7+) for patterns evaluated against untrusted input — it uses a linear-time NFA engine.
- **Avoid nested quantifiers** in patterns (`(a+)+`, `(.+)*`, `(a|a)+`) — rewrite to non-ambiguous alternatives.
- **Validate input length** before applying regex — reject excessively long strings at the controller layer.
- **Use `[GeneratedRegex]`** (.NET 7+ source generator) for compile-time optimization of static patterns.

```csharp
// ❌ INSECURE — no timeout, backtracking pattern on user input
bool valid = Regex.IsMatch(userEmail, @"^([a-zA-Z0-9]+\.?)+@[a-zA-Z0-9]+\.[a-zA-Z]{2,}$");
// Input "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa@" → catastrophic backtracking

// ❌ INSECURE — nested quantifier
bool match = Regex.IsMatch(input, @"^(\w+\s?)*$"); // ReDoS-prone

// ✅ SECURE — explicit timeout
try {
    bool valid = Regex.IsMatch(userEmail, @"^[^@\s]+@[^@\s]+\.[^@\s]+$",
        RegexOptions.None, TimeSpan.FromMilliseconds(100));
} catch (RegexMatchTimeoutException) {
    return false; // Treat timeout as invalid input
}

// ✅ SECURE — NonBacktracking (linear time, .NET 7+)
bool valid = Regex.IsMatch(userEmail, @"^[^@\s]+@[^@\s]+\.[^@\s]+$",
    RegexOptions.NonBacktracking);

// ✅ SECURE — source-generated regex (static, compile-time optimized)
[GeneratedRegex(@"^[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}$",
    RegexOptions.NonBacktracking)]
private static partial Regex EmailRegex();
```

---

## 9. HttpClient — TLS Validation and SSRF

**Vulnerability:** Bypassing TLS certificate validation by overriding `ServerCertificateCustomValidationCallback` to return `true` disables all certificate chain and hostname verification, making the application vulnerable to MITM attacks. Allowing user-controlled URLs in `HttpClient.GetAsync` enables Server-Side Request Forgery (SSRF), reaching internal services, metadata endpoints, and cloud provider APIs.

**References:** CWE-295, CWE-918, CVE-2022-34716 (.NET SSRF via HTTP redirects), OWASP SSRF Prevention Cheat Sheet

### Mandatory Rules

- **Never set `ServerCertificateCustomValidationCallback` to always return `true`** — this voids all TLS security.
- If custom CA trust is required, load the CA certificate into a custom `X509Chain` and validate properly.
- **Validate user-supplied URLs** before passing to `HttpClient`: enforce an allowlist of permitted hostnames, reject `localhost`, `169.254.0.0/16` (link-local), RFC 1918 ranges, `file://`, `gopher://`, and other non-HTTP schemes.
- **Configure `AllowAutoRedirect = false`** when the destination domain must be controlled — validate the redirect target if following redirects.
- Use a **named `HttpClient`** configured through `IHttpClientFactory` — do not instantiate `HttpClient` directly in loops (socket exhaustion risk).

```csharp
// ❌ INSECURE — completely disables certificate verification
var handler = new HttpClientHandler {
    ServerCertificateCustomValidationCallback = (_, _, _, _) => true
};
var client = new HttpClient(handler);

// ❌ INSECURE — SSRF: user controls the URL
var url = request.Query["url"].ToString();
var response = await _httpClient.GetAsync(url); // SSRF to internal metadata service

// ✅ SECURE — custom CA (internal PKI) without disabling verification
var handler = new HttpClientHandler();
handler.ClientCertificates.Add(internalCert);
// Do NOT override ServerCertificateCustomValidationCallback

// ✅ SECURE — SSRF prevention with hostname allowlist
static readonly HashSet<string> _allowedHosts = ["api.example.com", "cdn.example.com"];

Uri SafeUrl(string userInput) {
    if (!Uri.TryCreate(userInput, UriKind.Absolute, out var uri))
        throw new ArgumentException("Invalid URL");
    if (uri.Scheme is not "https")
        throw new ArgumentException("Only HTTPS is allowed");
    if (!_allowedHosts.Contains(uri.Host))
        throw new ArgumentException("Host not in allowlist");
    return uri;
}
var response = await _httpClient.GetAsync(SafeUrl(userInput));
```

---

## 10. Logging and Sensitive Data

**Vulnerability:** Writing passwords, tokens, PII, connection strings, or full exception stack traces to log sinks exposes sensitive data to log aggregation systems, monitoring platforms, log files, and anyone with read access. Structured logging sinks (Serilog, NLog, Microsoft.Extensions.Logging) can serialize entire objects, inadvertently capturing sensitive properties.

**References:** CWE-312, CWE-532, OWASP Logging Cheat Sheet

### Mandatory Rules

- **Never log passwords, tokens, PII fields, or connection strings** — scrub or mask before logging. In ASP.NET Core, do not enable `Information` log level on `Microsoft.AspNetCore.Authentication.JwtBearer` — CVE-2021-34532 demonstrated that raw JWT tokens were logged at that level.
- When logging objects with structured logging (`{@object}`), use **DTOs that omit sensitive fields** or implement `IDestructuringPolicy` to redact.
- **Return generic error messages to clients** — log the `Exception.Message` + stack trace server-side only, never send it in HTTP responses.
- **Log security events** with sufficient context: user ID, IP, endpoint, action, result — but not the actual secret value.
- Set **log level guardrails** in production — never enable `Trace` or `Debug` in production without redaction policies.

```csharp
// ❌ INSECURE — logs plain-text password
_logger.LogInformation("User {user} logged in with password {password}", username, password);

// ❌ INSECURE — serializes full request body (may include credit card, token)
_logger.LogDebug("Request received: {@request}", httpContext.Request);

// ❌ INSECURE — returns stack trace to client
catch (Exception ex) {
    return StatusCode(500, ex.ToString()); // Exposes internals
}

// ✅ SECURE — log only what is needed, redact sensitive fields
_logger.LogInformation("User {UserId} authenticated from {IpAddress}", userId, ipAddress);

// ✅ SECURE — generic client error, detailed server log
catch (Exception ex) {
    _logger.LogError(ex, "Unhandled exception processing request {RequestId}", requestId);
    return StatusCode(500, "An unexpected error occurred. Please try again later.");
}

// ✅ SECURE — Serilog destructuring policy redacts Password
Log.Logger = new LoggerConfiguration()
    .Destructure.ByTransforming<UserDto>(u => new { u.Id, u.Email, Password = "***" })
    .WriteTo.Console()
    .CreateLogger();
```

---

## 11. Reflection and Dynamic Code Execution

**Vulnerability:** `Assembly.Load` with attacker-controlled bytes, `CSharpCodeProvider.CompileAssemblyFromSource` (legacy Roslyn), `Type.InvokeMember` with untrusted type/method names, and `Expression.Lambda` with user-controlled expression trees enable arbitrary code execution. `DynamicMethod` and `Reflection.Emit` can bypass access modifiers.

**References:** CWE-470, CWE-913, OWASP Injection

### Mandatory Rules

- **Never load assemblies from user-supplied paths or byte arrays** unless the assembly is cryptographically signed and the signature is verified before loading.
- **Validate type and method names against an allowlist** before using `Type.GetType()`, `Activator.CreateInstance()`, or `MethodInfo.Invoke()`.
- **Never compile user-supplied C# source code** at runtime (e.g., `CSharpCodeProvider`, `Roslyn CSharpCompilation` with user source).
- If a plugin/extensibility model is needed, use **`AssemblyLoadContext`** with `FullTrustPermissionSet` disabled, run in a subprocess, or use **WebAssembly sandboxing**.
- Avoid `dynamic` keyword with user-controlled objects — it bypasses static type safety and can invoke unexpected members.

```csharp
// ❌ INSECURE — loads and executes attacker-supplied bytes
byte[] assemblyBytes = Convert.FromBase64String(request.Form["plugin"]);
var asm = Assembly.Load(assemblyBytes);
asm.GetType("Plugin").GetMethod("Run").Invoke(null, null);

// ❌ INSECURE — compiles user code at runtime
var compiler = new CSharpCodeProvider();
var result = compiler.CompileAssemblyFromSource(
    new CompilerParameters(), userCode); // RCE

// ❌ INSECURE — Type.GetType from user input
var type = Type.GetType(request.Query["type"]);
Activator.CreateInstance(type); // Attacker specifies any loaded type

// ✅ SECURE — allowlist-based factory
static readonly Dictionary<string, Func<IProcessor>> _registry = new() {
    ["csv"]  = () => new CsvProcessor(),
    ["json"] = () => new JsonProcessor(),
};

IProcessor CreateProcessor(string format) {
    if (!_registry.TryGetValue(format, out var factory))
        throw new ArgumentException($"Unsupported format: {format}");
    return factory();
}
```

---

## 12. Integer Overflow and Type Safety

**Vulnerability:** By default, C# arithmetic does not throw on integer overflow — it silently wraps around (unchecked context). Overflow in size calculations can cause heap buffer misallocation; in loop counters it can create infinite loops or skip security checks.

**References:** CWE-190, CWE-131

### Mandatory Rules

- **Use `checked` blocks** for arithmetic on user-controlled values where overflow would be dangerous (sizes, offsets, counts).
- **Validate ranges** before using values as array indices, allocation sizes, or loop bounds.
- Prefer **`long` / `ulong`** for quantities that might exceed `int` range; use `checked` when converting back.
- Avoid **unchecked upcasts** — `(int)userLong` silently truncates; validate the range first.
- In `unsafe` blocks, **every pointer offset arithmetic** must be range-checked to prevent buffer overruns.

```csharp
// ❌ INSECURE — overflow wraps silently (e.g., int.MaxValue + 1 = int.MinValue)
int size = headerCount * 4; // If headerCount ≈ 536,870,912 → size becomes negative
byte[] buffer = new byte[size]; // Large negative → ArgumentOutOfRangeException OR wrap-around allocation

// ❌ INSECURE — unchecked cast truncates
long userValue = long.Parse(input);
int idx = (int)userValue; // Truncates silently; may bypass bounds check

// ✅ SECURE — checked arithmetic
int size = checked(headerCount * 4); // Throws OverflowException if overflows

// ✅ SECURE — explicit range validation
if (userValue < 0 || userValue > int.MaxValue)
    throw new ArgumentOutOfRangeException(nameof(userValue));
int idx = (int)userValue;

// ✅ SECURE — safe buffer allocation with limit
const int MaxHeaders = 1024;
if (headerCount < 0 || headerCount > MaxHeaders)
    throw new ArgumentOutOfRangeException(nameof(headerCount), "Too many headers");
byte[] buffer = new byte[checked(headerCount * 4)];
```

---

## 13. ASP.NET Core Security — Headers, CORS, CSRF, Sessions

**Vulnerability:** Missing security headers allow clickjacking, MIME sniffing, and XSS escalation. Overly permissive CORS policies expose APIs to cross-origin credential theft. Missing CSRF protection allows state-changing requests from attacker-controlled pages. Improper session configuration enables session fixation and hijacking.

**References:** CWE-346, CWE-352, CWE-693, OWASP CSRF Prevention, OWASP Secure Headers Project

### Mandatory Rules

- **Add security headers** via middleware: `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`, `Content-Security-Policy`, `Strict-Transport-Security`.
- **Never configure `AllowAnyOrigin()` with `AllowCredentials()`** — this is rejected by browsers but signals a misconfigured policy.
- **Restrict CORS to an explicit allowlist** of trusted origins — never derive allowed origins from the request itself.
- **Enable CSRF protection** (Antiforgery) for all state-changing endpoints in server-rendered apps. REST/AJAX APIs using `Authorization: Bearer` tokens are not vulnerable to CSRF.
- **Set cookie security flags**: `HttpOnly = true`, `Secure = true`, `SameSite = SameSiteMode.Strict` (or `Lax`).
- **Regenerate session IDs** after authentication — prevents session fixation.

```csharp
// ❌ INSECURE — allow any origin with credentials (invalid but indicates intent)
app.UseCors(policy => policy
    .AllowAnyOrigin()
    .AllowCredentials());  // Throws at runtime; also a misconfig intent signal

// ❌ INSECURE — origin from request header (CORS bypass)
string origin = Request.Headers["Origin"];
policy.WithOrigins(origin).AllowCredentials(); // Attacker-controlled origin

// ❌ INSECURE — session cookie without Secure/HttpOnly
services.AddSession(opts => {
    opts.Cookie.Name = "session";
    // Missing: Secure, HttpOnly, SameSite
});

// ✅ SECURE — CORS with allowlist
builder.Services.AddCors(opts => opts.AddPolicy("Api", policy =>
    policy.WithOrigins("https://app.example.com", "https://admin.example.com")
          .AllowCredentials()
          .WithMethods("GET", "POST", "PUT", "DELETE")
          .WithHeaders("Authorization", "Content-Type")));

// ✅ SECURE — security headers middleware
app.Use(async (ctx, next) => {
    ctx.Response.Headers["X-Content-Type-Options"] = "nosniff";
    ctx.Response.Headers["X-Frame-Options"] = "DENY";
    ctx.Response.Headers["Referrer-Policy"] = "strict-origin-when-cross-origin";
    ctx.Response.Headers["Permissions-Policy"] = "geolocation=(), microphone=()";
    await next();
});

// ✅ SECURE — antiforgery for Razor Pages / MVC forms
builder.Services.AddAntiforgery(opts => {
    opts.Cookie.SecurePolicy = CookieSecurePolicy.Always;
    opts.Cookie.SameSite = SameSiteMode.Strict;
    opts.Cookie.HttpOnly = true;
    opts.HeaderName = "X-XSRF-TOKEN";
});

// ✅ SECURE — secure session cookie
builder.Services.AddSession(opts => {
    opts.IdleTimeout = TimeSpan.FromMinutes(20);
    opts.Cookie.HttpOnly = true;
    opts.Cookie.IsEssential = false;
    opts.Cookie.SecurePolicy = CookieSecurePolicy.Always;
    opts.Cookie.SameSite = SameSiteMode.Strict;
});

// ✅ SECURE — regenerate session after login (session fixation prevention)
HttpContext.Session.Clear();
await HttpContext.SignInAsync(principal);
```

---

## 14. Unsafe Code and Memory Safety

**Vulnerability:** The `unsafe` keyword allows pointer arithmetic, `stackalloc`, and pinned memory buffers. Off-by-one errors, missing bounds checks, and unchecked pointer increments cause heap/stack buffer overflows and memory corruption — the same class of bugs as C/C++.

**References:** CWE-119, CWE-125, CWE-787, OWASP Buffer Overflow

### Mandatory Rules

- **Minimize the `unsafe` surface area** — restrict to the smallest possible block/method and mark it with `[SecurityCritical]` where appropriate.
- **Always validate array lengths before pointer arithmetic** — never rely on the caller to enforce bounds.
- Prefer **`Span<T>` and `Memory<T>`** for high-performance buffer manipulation instead of raw pointers — they retain bounds checking.
- Use **`MemoryMarshal.Cast`** instead of pointer casts when reinterpreting buffer types.
- **Never use `stackalloc` with user-controlled size** — stack overflow kills the process and cannot be caught.
- Pair every `Marshal.AllocHGlobal` / `AllocCoTaskMem` with a corresponding `Free` in a `try/finally` block.

```csharp
// ❌ INSECURE — unchecked pointer offset → buffer overread
unsafe void ProcessBuffer(byte* data, int userLength) {
    for (int i = 0; i < userLength; i++) // No upper bound on data buffer size
        Console.Write((char)data[i]); // Read past allocated memory
}

// ❌ INSECURE — stackalloc with user-controlled size → stack overflow
unsafe void Allocate(int userSize) {
    byte* buffer = stackalloc byte[userSize]; // DoS if userSize is large
}

// ✅ SECURE — Span<T> with compile-time bounds enforcement
void ProcessBuffer(ReadOnlySpan<byte> data, int length) {
    if (length > data.Length) throw new ArgumentOutOfRangeException(nameof(length));
    var slice = data[..length]; // Bounds-checked, no pointer arithmetic needed
    foreach (var b in slice) Console.Write((char)b);
}

// ✅ SECURE — stackalloc with validated size cap
const int MaxStackSize = 1024;
int size = Math.Min(userSize, MaxStackSize);
Span<byte> buffer = size <= MaxStackSize
    ? stackalloc byte[size]
    : new byte[size]; // Fall back to heap for large inputs
```

---

## 15. Open Redirect

**Vulnerability:** Redirecting to a URL derived from user input (`returnUrl`, `next`, `redirect`) without validation allows attackers to craft phishing links (`https://app.example.com/login?returnUrl=https://evil.com`) that appear to originate from a trusted domain.

**References:** CWE-601, OWASP Unvalidated Redirects Cheat Sheet

### Mandatory Rules

- **Use `LocalRedirect` or `Url.IsLocalUrl()`** in ASP.NET Core for all redirect targets derived from user input — both reject absolute URLs pointing to external domains.
- Never call `Redirect(userInput)` or `Response.Redirect(userInput)` directly.
- If external redirects are required, validate against an explicit allowlist of permitted destination domains.

```csharp
// ❌ INSECURE — open redirect
return Redirect(Request.Query["returnUrl"]); // Attacker: returnUrl=https://evil.com

// ✅ SECURE — built-in local check
string returnUrl = Request.Query["returnUrl"];
if (!Url.IsLocalUrl(returnUrl))
    returnUrl = "/";
return LocalRedirect(returnUrl);

// ✅ SECURE — allowlist for external redirects
static readonly HashSet<string> _allowedHosts = ["partner.example.com"];
if (!Uri.TryCreate(returnUrl, UriKind.Absolute, out var uri) ||
    !_allowedHosts.Contains(uri.Host))
    return LocalRedirect("/");
return Redirect(returnUrl);
```

---

## 16. NuGet Supply Chain

**Vulnerability:** Compromised or dependency-confused NuGet packages, malicious pre/post-build scripts, and unpinned version ranges allow supply chain attacks. Packages with names similar to internal packages can be published to nuget.org and pulled preferentially over internal feeds.

**References:** CVE-2022-41032 (NuGet privilege escalation), CVE-2021-41773 (dependency confusion class), OWASP A06:2021

### Mandatory Rules

- **Pin exact package versions** in `<PackageReference>` — prefer `Version="X.Y.Z"` over ranges like `Version=">=X.Y"`.
- **Enable package lock files** (`dotnet nuget lock`) and check `packages.lock.json` into source control.
- **Configure private feeds** with `<clear />` to prevent pulling from nuget.org by default for internal packages.
- **Use `dotnet list package --vulnerable`** and integrate **`dotnet audit`** in CI.
- **Validate new packages** before adding — check the author identity, download count, last publish date, and source code availability.
- Enable **Central Package Management** (`Directory.Packages.props`) for monorepos to enforce consistent versions.

```xml
<!-- ❌ INSECURE — unpinned version range -->
<PackageReference Include="Newtonsoft.Json" Version="*" />
<PackageReference Include="Serilog" Version=">=3.0.0" />

<!-- ✅ SECURE — pinned exact version -->
<PackageReference Include="Newtonsoft.Json" Version="13.0.3" />
<PackageReference Include="Serilog" Version="4.0.2" />
```

```json
// ✅ SECURE — nuget.config: prefer internal feed, block public fallback for internal names
{
  "packageSources": {
    "clear": "",
    "add key=internal": "https://pkgs.dev.azure.com/myorg/_packaging/internal/nuget/v3/index.json",
    "add key=nuget": "https://api.nuget.org/v3/index.json"
  },
  "packageSourceMapping": {
    "internal": { "pattern": "MyCompany.*" },
    "nuget": { "pattern": "*" }
  }
}
```

---

## 17. Sensitive Data Exposure via Entity Framework / ORMs

**Vulnerability:** EF Core and Dapper can serialize entire model objects to API responses, revealing fields like `PasswordHash`, `SecurityStamp`, internal IDs, and audit fields. `Include()` chains on navigation properties can load and expose related sensitive entities.

**References:** CWE-200, OWASP API3:2023 Broken Object Property Level Authorization

### Mandatory Rules

- **Never return entity objects directly from API controllers** — always project to a DTO that includes only the fields needed by the client.
- **Mark sensitive properties** with `[JsonIgnore]` on the entity class as a last-resort safeguard, but prefer DTOs.
- Use **`Select(e => new UserDto { ... })`** in LINQ queries to project at the database layer — avoids loading sensitive columns at all.
- **Never expose primary keys** or surrogate database IDs in public API responses unless they are non-sensitive by design.

```csharp
// ❌ INSECURE — returns full entity including PasswordHash, SecurityStamp
[HttpGet("{id}")]
public async Task<User> GetUser(int id) =>
    await _ctx.Users.FindAsync(id);

// ❌ INSECURE — eager-loads sensitive navigation property
var users = await _ctx.Users.Include(u => u.PaymentMethods).ToListAsync();
return Ok(users);

// ✅ SECURE — project to DTO at query time
[HttpGet("{id}")]
public async Task<UserDto> GetUser(int id) =>
    await _ctx.Users
        .Where(u => u.Id == id)
        .Select(u => new UserDto { Id = u.Id, Name = u.Name, Email = u.Email })
        .FirstOrDefaultAsync()
    ?? throw new NotFoundException();
```

---

## CVE Reference Table

| CVE | Severity | Component | Description | Fixed In |
|-----|----------|-----------|-------------|----------|
| CVE-2020-0605 | High (8.8) | .NET Framework WinForms — BinaryFormatter | RCE via malicious `.resx` resource file triggering BinaryFormatter deserialization | .NET FX 4.8 Jan 2020 CU |
| CVE-2020-0606 | High (8.8) | .NET Framework WPF — BinaryFormatter | RCE via crafted BAML/XAML resource file using BinaryFormatter path | .NET FX 4.8 Jan 2020 CU |
| CVE-2020-1045 | High (7.5) | ASP.NET Core — cookie parser | Security bypass via semicolon/encoded chars in cookie name; allows session injection | ASP.NET Core 3.1.8, 2.1.22 |
| CVE-2020-1147 | High (7.8) | .NET Framework / .NET Core — `DataSet.ReadXml()` | RCE via malicious XML fed to `DataSet.ReadXml()` — type instantiation without validation | .NET Core 3.1.6, .NET FX 4.8 Jul 2020 CU |
| CVE-2021-26701 | Critical (9.8) | .NET Core / .NET 5 — `System.Text.Encodings.Web` | RCE via crafted input processed by the HTML encoder in ASP.NET Core responses | .NET 5.0.3, .NET Core 3.1.12 |
| CVE-2021-27076 | High (8.8) | `Microsoft.Identity.Web` 1.x — tenant ID validation | Multi-tenant auth bypass: `tid` claim not validated, allowing cross-tenant impersonation | `Microsoft.Identity.Web` 1.9.1 |
| CVE-2021-34532 | Medium (5.5) | ASP.NET Core JWT middleware — info disclosure | Raw JWT tokens written to application logs at Info level when debug logging is enabled | .NET 5.0.9, ASP.NET Core 3.1.18 |
| CVE-2023-29337 | High (7.5) | NuGet client — package source confusion | Dependency confusion via NuGet restore; allows malicious package substitution | .NET SDK 7.0.304, 6.0.316 |
| CVE-2023-33170 | Critical (9.8) | ASP.NET Core — authentication race condition | Account lockout bypass via concurrent requests resetting the lockout counter | .NET 7.0.9, .NET 6.0.21 |
| CVE-2024-21319 | Medium (6.8) | `Microsoft.IdentityModel` / JWT validation | DoS via malformed JWT causing excessive CPU in token validation (algorithmic complexity) | `Microsoft.IdentityModel` 7.1.2, ASP.NET Core 8.0.1 |
| CVE-2024-43483 | High (7.5) | .NET 8 — `System.Net.Http.HttpClient` | DoS via malformed HTTP response headers causing excessive processing | .NET 8.0.10, .NET 6.0.35 |
| CVE-2024-43485 | High (7.5) | .NET 8 — `System.Text.Json` | DoS via deeply nested JSON causing `StackOverflowException` (no depth limit by default) | .NET 8.0.10, .NET 9.0 RC2 |

---

## Security Checklist

### Deserialization
- [ ] `BinaryFormatter`, `SoapFormatter`, `LosFormatter`, `NetDataContractSerializer` are not used anywhere
- [ ] `JsonSerializerSettings.TypeNameHandling` is `None` (or uses a strict `SerializationBinder`)
- [ ] `System.Text.Json` deserialization has `MaxDepth` set (default 64; set to ≤ 32 for untrusted input)
- [ ] `DataSet.ReadXml()` / `DataTable.ReadXml()` are not called on untrusted XML
- [ ] No custom `ISerializationSurrogate` accepting untrusted data

### SQL & Data Access
- [ ] All SQL queries use parameterized commands or EF Core LINQ
- [ ] `FromSqlInterpolated` is used instead of `FromSqlRaw` for dynamic queries
- [ ] Dynamic `ORDER BY` / column names validated against allowlist

### XML & XXE
- [ ] Every `XmlReader` / `XmlDocument` has `DtdProcessing = Prohibit` and `XmlResolver = null`
- [ ] `XslCompiledTransform` loaded with `enableDocumentFunction: false, enableScript: false`

### Command Injection
- [ ] All `Process.Start` calls use `UseShellExecute = false`
- [ ] Arguments passed via `ArgumentList` collection, not concatenated `Arguments` string

### Cryptography
- [ ] AES-256-GCM used for symmetric encryption
- [ ] No MD5, SHA-1, DES, 3DES, ECB mode, or static IV
- [ ] `RandomNumberGenerator.GetBytes()` used for all tokens and IVs
- [ ] `CryptographicOperations.FixedTimeEquals` used for HMAC/token comparisons
- [ ] Passwords hashed with PBKDF2, bcrypt, or Argon2id

### Path Traversal
- [ ] All file paths constructed from user input are canonicalized with `Path.GetFullPath()` and base directory verified
- [ ] Uploaded files renamed to server-generated UUIDs

### TLS & HttpClient
- [ ] `ServerCertificateCustomValidationCallback` is never set to always return `true`
- [ ] All `HttpClient` instances from `IHttpClientFactory` (not manually instantiated)
- [ ] User-controlled URLs validated against hostname allowlist

### ASP.NET Core
- [ ] CORS allows only specific trusted origins
- [ ] Antiforgery enabled for state-changing HTML form endpoints
- [ ] All cookies: `HttpOnly = true`, `Secure = true`, `SameSite = Strict`
- [ ] Security headers set: `X-Content-Type-Options`, `X-Frame-Options`, `HSTS`, `CSP`
- [ ] Session IDs regenerated after authentication

### Logging
- [ ] No passwords, tokens, or PII logged
- [ ] Generic error messages returned to clients; details logged server-side only
- [ ] Serilog/NLog destructuring policies mask sensitive fields

### Input Validation
- [ ] All regex applied to user input has a `TimeSpan` timeout or uses `NonBacktracking`
- [ ] `checked` arithmetic used for size calculations derived from user input
- [ ] Open redirects use `Url.IsLocalUrl()` or `LocalRedirect()`

### Supply Chain
- [ ] All `PackageReference` versions are pinned exactly
- [ ] `packages.lock.json` committed to source control
- [ ] `dotnet list package --vulnerable` runs in CI
- [ ] Internal package names registered on nuget.org to prevent dependency confusion

---

## Tooling

| Tool | Purpose | Command |
|------|---------|---------|
| [dotnet audit](https://learn.microsoft.com/en-us/dotnet/core/tools/dotnet-nuget-why) | Vulnerability scan for NuGet packages | `dotnet list package --vulnerable` |
| [Security Code Scan (VS Extension)](https://security-code-scan.github.io/) | Roslyn analyzer for SQLi, XSS, XXE, CSRF, SSRF | Add NuGet: `SecurityCodeScan.VS2019` |
| [Puma Scan](https://pumascan.com/) | Roslyn analyzer for injection, path traversal, weak crypto | Add NuGet: `Puma.Security.Rules` |
| [Semgrep .NET rules](https://semgrep.dev/r#csharp) | Static analysis with C# rulesets | `semgrep --config "p/csharp"` |
| [OWASP Dependency-Check](https://owasp.org/www-project-dependency-check/) | CVE scanning for all project dependencies | `dependency-check --project . --scan .` |
| [Gitleaks](https://gitleaks.io/) | Secret scanning in Git history | `gitleaks detect --source .` |
| [dotnet-outdated](https://github.com/dotnet-outdated/dotnet-outdated) | Identify outdated NuGet packages | `dotnet outdated` |
| [BinSkim](https://github.com/microsoft/binskim) | PE/EFI binary security analyzer (compiler flags, CFG, ASLR) | `binskim analyze bin/**/*.dll` |
| [Microsoft Threat Modeling Tool](https://aka.ms/tmt) | Architecture-level threat model for .NET apps | GUI application |

---

*Released under [CC BY-SA 4.0](https://creativecommons.org/licenses/by-sa/4.0/). Based on Microsoft Security Advisories, OWASP .NET Cheat Sheets, and NIST/MITRE vulnerability data.*
