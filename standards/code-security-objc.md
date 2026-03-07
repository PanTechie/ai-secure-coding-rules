# 🍎 Objective-C Security Rules

> **Standard:** Security rules for Objective-C applications targeting iOS 14+ and macOS 12+, including UIKit, AppKit, Foundation, and Core Foundation frameworks.
> **Sources:** Apple Platform Security Guide, OWASP Mobile Top 10:2024, OWASP MASVS 2.1, SEI CERT C Coding Standard, NVD/CVE Database, GitHub Advisory Database, iOS Security Research (Project Zero, ZecOps, Citizen Lab)
> **Version:** 1.0.0
> **Last updated:** March 2026
> **Scope:** Objective-C and Objective-C++ targeting Apple platforms. Language-level and framework-level vulnerabilities. Does not duplicate the generic mobile platform rules in code-security-mobile.md; instead focuses on Objective-C-specific pitfalls arising from its C runtime, dynamic dispatch model, and Apple framework APIs.

---

## General Instructions

Apply these rules when writing or reviewing Objective-C or Objective-C++ code. Objective-C is uniquely dangerous because it combines a C runtime (with all C memory-safety hazards: buffer overflows, format strings, use-after-free) with a highly dynamic message-passing runtime (method swizzling, `performSelector:`, KVC injection, `NSClassFromString`). Apple's ARC eliminates many retain/release bugs but does not prevent C-level memory errors, Core Foundation misuse, or runtime introspection attacks. Always treat the device as untrusted: binaries can be extracted, debugged with Frida/lldb, and runtime behavior can be altered without code modifications.

---

## 1. C-Inherited Buffer Overflows

**Vulnerability:** Objective-C code routinely interops with C APIs — particularly when working with audio, video, networking, and low-level I/O. Functions like `strcpy`, `strcat`, `sprintf`, and `gets` do not check destination buffer size, allowing attackers to overwrite adjacent stack or heap memory, enabling arbitrary code execution or crashes. NSData-to-C-buffer copies without length checks are a common source of heap overflows in Apple framework code.

**References:** CWE-120, CWE-122, CWE-131, SEI CERT C MSC33-C

### Mandatory Rules

- **Use bounded string functions exclusively** — replace `strcpy` with `strlcpy`, `strcat` with `strlcat`, `sprintf` with `snprintf`, and never use `gets` under any circumstances.
- **Validate NSData length before copying to C buffers** — always compare `[data length]` against the destination buffer size before calling `memcpy` or `[data getBytes:length:]`.
- **Allocate dynamic buffers with explicit size checks** — use `calloc` and verify the returned pointer is non-NULL before writing; use `SIZE_MAX` overflow checks when computing allocation sizes.

```objc
// ❌ INSECURE — strcpy does not check destination size; overflow if username > 63 bytes
char buffer[64];
const char *username = [userInput UTF8String];
strcpy(buffer, username);  // heap/stack smash if username is >= 64 bytes

// ✅ SECURE — strlcpy always null-terminates and respects the destination size
char buffer[64];
const char *username = [userInput UTF8String];
strlcpy(buffer, username, sizeof(buffer));
```

```objc
// ❌ INSECURE — memcpy with unchecked NSData length; attacker-controlled data can overflow stack buffer
char buf[256];
memcpy(buf, [networkData bytes], [networkData length]);  // no bounds check

// ✅ SECURE — validate length before copy
char buf[256];
NSUInteger dataLen = [networkData length];
if (dataLen > sizeof(buf)) {
    // reject or truncate
    return;
}
memcpy(buf, [networkData bytes], dataLen);
```

```objc
// ❌ INSECURE — sprintf with format arg from user input; no length limit
char msg[128];
sprintf(msg, userSuppliedFormat, value);  // format string + overflow

// ✅ SECURE — snprintf enforces maximum bytes written
char msg[128];
snprintf(msg, sizeof(msg), "%s: %d", label, value);
```

---

## 2. Format String Injection via NSLog and NSString

**Vulnerability:** `NSLog` and `[NSString stringWithFormat:]` accept a format string as their first argument. When user-controlled data is passed directly as the format string rather than as a format argument, attackers can use `%n` to write to arbitrary memory addresses, `%x`/`%p` to dump stack or heap contents, and `%s` to read from arbitrary pointers. This is a well-known C vulnerability class that persists in Objective-C because of the variadic C calling convention used by NS_FORMAT_FUNCTION.

**References:** CWE-134, CVE-2014-1347

### Mandatory Rules

- **Never pass user-controlled data as the first argument to `NSLog`, `NSString stringWithFormat:`, `[NSException raise:format:]`, or any NS_FORMAT_FUNCTION** — always use a literal format string with `%@` as the argument.
- **Treat any string from an external source (network, file, user input, pasteboard) as a format argument, not a format string.**
- **Enable the `-Wformat-nonliteral` compiler warning** and resolve all occurrences before shipping.

```objc
// ❌ INSECURE — userMessage is passed as format string; %n writes, %x stack leaks
NSString *userMessage = request.body[@"message"];
NSLog(userMessage);  // format string injection

// ✅ SECURE — literal format string; userMessage is a safe argument
NSString *userMessage = request.body[@"message"];
NSLog(@"%@", userMessage);
```

```objc
// ❌ INSECURE — stringWithFormat: with user-controlled format
NSString *label = [NSString stringWithFormat:userInput];

// ✅ SECURE — user input is always an argument, never the format
NSString *label = [NSString stringWithFormat:@"%@", userInput];
```

```objc
// ❌ INSECURE — NSException with user-controlled format string
[NSException raise:NSInvalidArgumentException format:userInput];

// ✅ SECURE — literal format string
[NSException raise:NSInvalidArgumentException format:@"Invalid argument: %@", userInput];
```

---

## 3. Objective-C Runtime Abuse (KVC Injection and Dynamic Dispatch)

**Vulnerability:** The Objective-C runtime's dynamic nature enables powerful patterns, but passing user-controlled strings to KVC (`setValue:forKeyPath:`, `valueForKeyPath:`), `NSClassFromString`, `NSSelectorFromString`, or `performSelector:` allows attackers to invoke arbitrary methods, access private properties, execute aggregate operators (e.g., `@sum`, `@avg`), or instantiate arbitrary classes. KVC aggregate operator injection (e.g., `@"@sum.someField"`) can trigger unintended behavior or denial of service. This class of vulnerability was exploited in CVE-2012-3725 (Apple iOS Safari) and remains relevant in any app that processes untrusted key paths.

**References:** CWE-470, CWE-913, CVE-2012-3725

### Mandatory Rules

- **Never pass user-controlled strings to `setValue:forKeyPath:`, `valueForKeyPath:`, `valueForKey:`, `setValue:forKey:`** — validate against an explicit allowlist of permitted key names before use.
- **Never pass user input to `NSClassFromString` or `NSSelectorFromString`** — these functions resolve strings to live class/method pointers; treat them as equivalent to `dlopen` + `dlsym`.
- **Never call `performSelector:` with a selector derived from user input** — use a dispatch table (NSDictionary mapping strings to blocks) instead.
- **Sanitize keyPath strings to reject `@` operator prefixes** — check that the string does not begin with `@` before using it in any KVC call.

```objc
// ❌ INSECURE — attacker sets keyPath to "@sum.salary" or "private._internalState"
NSString *keyPath = [request parameterForKey:@"field"];
id value = [userObject valueForKeyPath:keyPath];  // KVC operator injection + private property access

// ✅ SECURE — explicit allowlist of permitted key names; reject anything not in the list
NSSet *allowedKeys = [NSSet setWithObjects:@"displayName", @"email", @"avatarURL", nil];
NSString *key = [request parameterForKey:@"field"];
if (![allowedKeys containsObject:key]) {
    [self respondWithError:@"Invalid field"];
    return;
}
id value = [userObject valueForKey:key];
```

```objc
// ❌ INSECURE — arbitrary class instantiation from user-supplied string
NSString *className = [params objectForKey:@"handler"];
Class handlerClass = NSClassFromString(className);
id handler = [[handlerClass alloc] init];  // instantiates any class in the binary

// ✅ SECURE — dispatch table maps strings to known, vetted handlers
NSDictionary *handlers = @{
    @"image": [ImageHandler class],
    @"text":  [TextHandler class],
};
Class handlerClass = handlers[[params objectForKey:@"handler"]];
if (!handlerClass) { return; }
id handler = [[handlerClass alloc] init];
```

```objc
// ❌ INSECURE — performSelector with user-controlled selector name
SEL sel = NSSelectorFromString([request parameterForKey:@"action"]);
[self performSelector:sel];  // arbitrary method invocation

// ✅ SECURE — block-based dispatch table; no dynamic selector resolution
NSDictionary<NSString *, void(^)(void)> *actions = @{
    @"refresh": ^{ [self refreshData]; },
    @"logout":  ^{ [self logoutUser]; },
};
void (^action)(void) = actions[[request parameterForKey:@"action"]];
if (action) { action(); }
```

---

## 4. NSKeyedUnarchiver Deserialization

**Vulnerability:** `[NSKeyedUnarchiver unarchiveObjectWithData:]` deserializes an NSCoding-compliant object graph from arbitrary data without restricting which classes may be instantiated. An attacker who controls the archived data can trigger instantiation of any class in the process's address space, invoke `initWithCoder:` on classes that perform dangerous operations during initialization, and chain multiple objects to achieve arbitrary code execution. This is the Objective-C analogue of Java deserialization gadget chains. CVE-2019-8641 is a critical Apple-internal use of NSKeyedUnarchiver that enabled RCE on iOS 12.

**References:** CWE-502, CVE-2019-8641

### Mandatory Rules

- **Never use `+[NSKeyedUnarchiver unarchiveObjectWithData:]` or `+[NSKeyedUnarchiver unarchiveObjectWithFile:]`** — both are deprecated and unsafe; they allow arbitrary class instantiation.
- **Always use `decodeTopLevelObjectOfClasses:forKey:error:` with an explicit `NSSet` of allowed classes** — this restricts instantiation to only the types you expect.
- **Validate the decoded object's type with `isKindOfClass:` even after class-restricted decoding** — defense in depth against future API changes.
- **Treat all archived data from network, files, or pasteboard as untrusted** — apply class restrictions regardless of apparent origin.

```objc
// ❌ INSECURE — allows any NSCoding class to be instantiated from the archive
NSData *archived = [NSData dataWithContentsOfFile:filePath];
id object = [NSKeyedUnarchiver unarchiveObjectWithData:archived];  // gadget chain possible

// ✅ SECURE — restricted class set; only known-safe classes can be instantiated
NSData *archived = [NSData dataWithContentsOfFile:filePath];
NSError *error = nil;
NSKeyedUnarchiver *unarchiver = [[NSKeyedUnarchiver alloc] initForReadingFromData:archived
                                                                            error:&error];
if (error) { return; }
unarchiver.requiresSecureCoding = YES;

NSSet *allowedClasses = [NSSet setWithObjects:[UserProfile class], [NSString class],
                                               [NSNumber class], [NSArray class], nil];
UserProfile *profile = [unarchiver decodeTopLevelObjectOfClasses:allowedClasses
                                                          forKey:NSKeyedArchiveRootObjectKey
                                                           error:&error];
if (error || ![profile isKindOfClass:[UserProfile class]]) {
    // reject malformed archive
    return;
}
```

---

## 5. NSPredicate Format String Injection (Core Data)

**Vulnerability:** `[NSPredicate predicateWithFormat:]` parses a SQL-like predicate expression with support for key paths, operators, and literals. When user input is interpolated directly into the format string (not passed as a `%@` argument), attackers can inject arbitrary predicate logic — bypassing filters, exposing all records, or crashing the app via malformed expressions. This is the Core Data equivalent of SQL injection and is trivially exploitable whenever a search field's value is concatenated into the format string.

**References:** CWE-943, CWE-89

### Mandatory Rules

- **Always use format argument placeholders (`%@`, `%K`, `%d`) to pass user-controlled values into `NSPredicate`** — never use string concatenation or `[NSString stringWithFormat:]` to build a predicate format string.
- **Use `%K` for key paths and `%@` for values** — `%K` applies key path validation; `%@` ensures the value is treated as a literal, not interpreted as predicate syntax.
- **Validate and allowlist key path strings before using them with `%K`** — user-controlled key names can still access private properties even when using `%K`.

```objc
// ❌ INSECURE — user input concatenated into predicate format; inject "1=1" to bypass filter
NSString *search = userTextField.text;
NSString *format = [NSString stringWithFormat:@"name = '%@'", search];
NSPredicate *predicate = [NSPredicate predicateWithFormat:format];  // predicate injection

// ✅ SECURE — user input passed as %@ argument; treated as a string literal, not predicate syntax
NSString *search = userTextField.text;
NSPredicate *predicate = [NSPredicate predicateWithFormat:@"name = %@", search];
```

```objc
// ❌ INSECURE — user-controlled field name concatenated into format string
NSString *field = [params objectForKey:@"sortField"];
NSPredicate *pred = [NSPredicate predicateWithFormat:
    [NSString stringWithFormat:@"%@ CONTAINS[cd] %@", field, searchTerm]];

// ✅ SECURE — %K for key path (validated), %@ for value
NSSet *allowedFields = [NSSet setWithObjects:@"name", @"email", @"city", nil];
NSString *field = [params objectForKey:@"sortField"];
if (![allowedFields containsObject:field]) { return; }
NSPredicate *pred = [NSPredicate predicateWithFormat:@"%K CONTAINS[cd] %@", field, searchTerm];
```

---

## 6. Insecure Data Storage (NSUserDefaults, Plist, Files)

**Vulnerability:** `NSUserDefaults` persists data to an unencrypted plist file in the app's Library/Preferences directory. On a jailbroken device or via iTunes backup (without encryption enabled), these files are trivially readable. Writing sensitive data to the Documents/ directory exposes it via iTunes File Sharing if `UIFileSharingEnabled` is set. Files created without `NSFileProtectionComplete` are accessible even when the device is locked, enabling cold-boot or forensic extraction attacks.

**References:** CWE-312, CWE-922, OWASP MASVS MSTG-STORAGE-1

### Mandatory Rules

- **Never store authentication tokens, passwords, session cookies, or cryptographic keys in `NSUserDefaults`** — use the Keychain for secrets.
- **Set `NSFileProtectionComplete` on all files containing sensitive data** — this ties file encryption to the user's passcode and ensures the file is inaccessible when the device is locked.
- **Do not write sensitive data to the Documents/ directory** — use the Application Support directory with appropriate file protection attributes.
- **Audit all `NSUserDefaults` writes** — only non-sensitive preferences (theme, language, UI state) are appropriate.

```objc
// ❌ INSECURE — token stored in unencrypted NSUserDefaults plist
NSString *token = [authResponse objectForKey:@"access_token"];
[[NSUserDefaults standardUserDefaults] setObject:token forKey:@"auth_token"];

// ✅ SECURE — token stored in Keychain with appropriate accessibility
NSDictionary *keychainQuery = @{
    (__bridge id)kSecClass:       (__bridge id)kSecClassGenericPassword,
    (__bridge id)kSecAttrService: @"com.example.app",
    (__bridge id)kSecAttrAccount: @"auth_token",
    (__bridge id)kSecValueData:   [token dataUsingEncoding:NSUTF8StringEncoding],
    (__bridge id)kSecAttrAccessible: (__bridge id)kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
};
SecItemAdd((__bridge CFDictionaryRef)keychainQuery, NULL);
```

```objc
// ❌ INSECURE — sensitive report written to Documents/ without file protection
NSString *path = [NSSearchPathForDirectoriesInDomains(NSDocumentDirectory, NSUserDomainMask, YES) firstObject];
NSString *filePath = [path stringByAppendingPathComponent:@"report.json"];
[sensitiveData writeToFile:filePath atomically:YES];  // no file protection

// ✅ SECURE — written with NSFileProtectionComplete; inaccessible while device is locked
NSString *path = [NSSearchPathForDirectoriesInDomains(NSApplicationSupportDirectory, NSUserDomainMask, YES) firstObject];
NSString *filePath = [path stringByAppendingPathComponent:@"report.json"];
NSDictionary *attrs = @{ NSFileProtectionKey: NSFileProtectionComplete };
[[NSFileManager defaultManager] createFileAtPath:filePath
                                        contents:sensitiveData
                                      attributes:attrs];
```

---

## 7. Keychain Security

**Vulnerability:** The iOS Keychain is the correct storage mechanism for secrets, but its security level is determined by the `kSecAttrAccessible` attribute. Using `kSecAttrAccessibleAlways` or `kSecAttrAccessibleAlwaysThisDeviceOnly` makes items readable even when the device is locked and the passcode has never been entered — enabling extraction via forensic tools (GrayKey, Cellebrite) or from an unlocked backup. Biometric-protected items backed only by `LAContext` are bypassable via Frida hooking of the `evaluatePolicy:reply:` callback.

**References:** CWE-312, OWASP MASVS MSTG-STORAGE-1

### Mandatory Rules

- **Never use `kSecAttrAccessibleAlways` or `kSecAttrAccessibleAlwaysThisDeviceOnly`** — these make Keychain items readable at any time, even after device reboot without passcode entry.
- **Use `kSecAttrAccessibleWhenUnlockedThisDeviceOnly` for general secrets** — items are readable only while the device is unlocked; the `ThisDeviceOnly` suffix prevents iCloud/iTunes backup migration.
- **Use `kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly` only for items needed by background tasks** — minimizes the window of accessibility to after first unlock post-reboot.
- **Protect high-value secrets with `SecAccessControlCreateWithFlags` and `kSecAccessControlBiometryCurrentSet`** — the secret is cryptographically protected by biometric enrollment; a Frida hook on `LAContext` cannot bypass it.

```objc
// ❌ INSECURE — item accessible at all times, even when device is locked
NSDictionary *query = @{
    (__bridge id)kSecClass:           (__bridge id)kSecClassGenericPassword,
    (__bridge id)kSecAttrService:     @"com.example.app",
    (__bridge id)kSecAttrAccount:     @"private_key",
    (__bridge id)kSecValueData:       keyData,
    (__bridge id)kSecAttrAccessible:  (__bridge id)kSecAttrAccessibleAlways,  // ❌
};
SecItemAdd((__bridge CFDictionaryRef)query, NULL);

// ✅ SECURE — item accessible only when device is unlocked; not backed up
CFErrorRef error = NULL;
SecAccessControlRef acl = SecAccessControlCreateWithFlags(
    kCFAllocatorDefault,
    kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
    kSecAccessControlBiometryCurrentSet | kSecAccessControlOr | kSecAccessControlDevicePasscode,
    &error
);
NSDictionary *query = @{
    (__bridge id)kSecClass:             (__bridge id)kSecClassGenericPassword,
    (__bridge id)kSecAttrService:       @"com.example.app",
    (__bridge id)kSecAttrAccount:       @"private_key",
    (__bridge id)kSecValueData:         keyData,
    (__bridge id)kSecAttrAccessControl: (__bridge_transfer id)acl,
};
SecItemAdd((__bridge CFDictionaryRef)query, NULL);
```

---

## 8. TLS and Certificate Validation

**Vulnerability:** `NSURLSession` and `NSURLConnection` delegate methods allow applications to override TLS certificate evaluation. Implementing `didReceiveAuthenticationChallenge:` to unconditionally trust the server certificate (by creating a credential for any challenge) disables certificate validation entirely, allowing man-in-the-middle attacks on all traffic. The `NSAllowsArbitraryLoads: YES` key in Info.plist disables App Transport Security globally, removing TLS enforcement for all connections. `allowsAnyHTTPSCertificateForHost:` (private API) is commonly found in test code inadvertently shipped in release builds.

**References:** CWE-295, CVE-2022-26775, OWASP MASVS MSTG-NETWORK-3

### Mandatory Rules

- **Never return `NSURLSessionAuthChallengeUseCredential` for an unevaluated server trust** — always call `SecTrustEvaluateWithError` and only proceed if it returns YES.
- **Remove all `NSAllowsArbitraryLoads: YES` entries from Info.plist before production builds** — use per-domain `NSExceptionAllowsInsecureHTTPLoads` only during transition, with a documented sunset plan.
- **Implement certificate pinning** for connections to your own backend — pin the Subject Public Key Info (SPKI) hash rather than the leaf certificate to survive certificate rotations.
- **Use `SecTrustSetAnchorCertificates` + `SecTrustSetAnchorCertificatesOnly` for custom CA pinning** — this integrates with the system trust evaluation engine.

```objc
// ❌ INSECURE — accepts any certificate unconditionally; trivially MITM'd
- (void)URLSession:(NSURLSession *)session
didReceiveChallenge:(NSURLAuthenticationChallenge *)challenge
 completionHandler:(void (^)(NSURLSessionAuthChallengeDisposition, NSURLCredential *))completionHandler {
    NSURLCredential *credential = [NSURLCredential credentialForTrust:challenge.protectionSpace.serverTrust];
    completionHandler(NSURLSessionAuthChallengeUseCredential, credential);  // no validation
}

// ✅ SECURE — evaluates trust; rejects invalid chains
- (void)URLSession:(NSURLSession *)session
didReceiveChallenge:(NSURLAuthenticationChallenge *)challenge
 completionHandler:(void (^)(NSURLSessionAuthChallengeDisposition, NSURLCredential *))completionHandler {
    SecTrustRef serverTrust = challenge.protectionSpace.serverTrust;
    CFErrorRef cfError = NULL;
    BOOL trusted = SecTrustEvaluateWithError(serverTrust, &cfError);
    if (trusted) {
        // optionally validate SPKI hash here for pinning
        NSURLCredential *credential = [NSURLCredential credentialForTrust:serverTrust];
        completionHandler(NSURLSessionAuthChallengeUseCredential, credential);
    } else {
        if (cfError) CFRelease(cfError);
        completionHandler(NSURLSessionAuthChallengeCancelAuthenticationChallenge, nil);
    }
}
```

---

## 9. SQL Injection (FMDB / sqlite3)

**Vulnerability:** When SQL queries are constructed by concatenating user-supplied strings, attackers can inject SQL syntax to read all rows, bypass WHERE clauses, delete data, or (with ATTACH) access other databases. FMDB's `executeQuery:` accepts format-style arguments, but developers frequently use `[NSString stringWithFormat:]` to pre-build the query string, bypassing FMDB's parameterization entirely. Direct use of `sqlite3_exec` with formatted strings has the same vulnerability at the C level.

**References:** CWE-89, CWE-943

### Mandatory Rules

- **Use FMDB's argument array or variadic parameterization exclusively** — pass user values as `withArgumentsInArray:` or as variadic `...` arguments after the SQL string, never via `[NSString stringWithFormat:]`.
- **Use `sqlite3_prepare_v2` + `sqlite3_bind_*` for all `sqlite3` C API calls** — never pass user input to `sqlite3_exec` directly.
- **Validate and allowlist column and table names before use** — parameterized queries cannot parameterize identifiers; use a hardcoded whitelist for column/table selection.

```objc
// ❌ INSECURE — userId injected into SQL string; ' OR '1'='1 dumps entire table
NSString *query = [NSString stringWithFormat:@"SELECT * FROM users WHERE id = '%@'", userId];
FMResultSet *rs = [db executeQuery:query];  // SQL injection

// ✅ SECURE — userId passed as bound argument; FMDB uses sqlite3_bind internally
FMResultSet *rs = [db executeQuery:@"SELECT * FROM users WHERE id = ?"
              withArgumentsInArray:@[userId]];
```

```objc
// ❌ INSECURE — sqlite3_exec with formatted string
char sql[512];
snprintf(sql, sizeof(sql), "DELETE FROM sessions WHERE token = '%s'", tokenCStr);
sqlite3_exec(db, sql, NULL, NULL, NULL);  // SQL injection at C level

// ✅ SECURE — prepared statement with sqlite3_bind_text
sqlite3_stmt *stmt;
sqlite3_prepare_v2(db, "DELETE FROM sessions WHERE token = ?", -1, &stmt, NULL);
sqlite3_bind_text(stmt, 1, tokenCStr, -1, SQLITE_TRANSIENT);
sqlite3_step(stmt);
sqlite3_finalize(stmt);
```

---

## 10. WebView Security (UIWebView and WKWebView)

**Vulnerability:** `UIWebView` (deprecated but still present in millions of apps) and `WKWebView` both allow loading arbitrary HTML and executing JavaScript against the loaded content. `stringByEvaluatingJavaScriptFromString:` (UIWebView) and `evaluateJavaScript:completionHandler:` (WKWebView) inject script into the WebView's JavaScript context. If that script contains user-controlled content, it is equivalent to stored XSS. `loadHTMLString:baseURL:` with a `file://` base URL gives the page access to local files via XMLHttpRequest. `WKUserContentController` message handlers receive messages from untrusted web content, creating an injection surface into native code.

**References:** CWE-79, CWE-749, OWASP MASVS MSTG-PLATFORM-5

### Mandatory Rules

- **Never pass user-controlled strings directly to `evaluateJavaScript:` or `stringByEvaluatingJavaScriptFromString:`** — JSON-encode any dynamic values before embedding them in JavaScript strings.
- **Avoid `UIWebView` entirely** — it is deprecated, unpatched for many vulnerabilities, and will be rejected by App Store review in future SDK versions; migrate to `WKWebView`.
- **Set `baseURL` to `nil` or an `https://` origin** when calling `loadHTMLString:baseURL:` with user content — a `file://` base URL grants the page local file system access.
- **Validate `WKScriptMessage` payloads** in `userContentController:didReceiveScriptMessage:` — treat message body as untrusted input; validate type and values before acting on them.
- **Implement `decidePolicyForNavigationAction:` in the `WKNavigationDelegate`** — reject navigation to `javascript:` URLs, `file://` URLs, and unexpected schemes.

```objc
// ❌ INSECURE — user-supplied HTML loaded with file:// base; XSS + local file read
NSString *html = [NSString stringWithFormat:@"<h1>%@</h1>", userContent];
[webView loadHTMLString:html baseURL:[NSURL fileURLWithPath:@"/"]];

// ✅ SECURE — user content HTML-escaped; base URL is nil (no origin for file: access)
NSString *escaped = [userContent stringByReplacingOccurrencesOfString:@"&" withString:@"&amp;"];
escaped = [escaped stringByReplacingOccurrencesOfString:@"<" withString:@"&lt;"];
escaped = [escaped stringByReplacingOccurrencesOfString:@">" withString:@"&gt;"];
NSString *html = [NSString stringWithFormat:@"<html><body><p>%@</p></body></html>", escaped];
[webView loadHTMLString:html baseURL:nil];
```

```objc
// ❌ INSECURE — user name injected directly into JavaScript; XSS if name contains quotes
NSString *js = [NSString stringWithFormat:@"displayUser('%@')", userName];
[webView evaluateJavaScript:js completionHandler:nil];

// ✅ SECURE — value JSON-encoded before embedding; JavaScript cannot break out of the string
NSData *jsonData = [NSJSONSerialization dataWithJSONObject:@{@"name": userName} options:0 error:nil];
NSString *jsonStr = [[NSString alloc] initWithData:jsonData encoding:NSUTF8StringEncoding];
NSString *js = [NSString stringWithFormat:@"displayUser(%@.name)", jsonStr];
[webView evaluateJavaScript:js completionHandler:nil];
```

---

## 11. URL Scheme and Deep Link Hijacking

**Vulnerability:** Custom URL schemes (e.g., `myapp://`) can be registered by any app installed on the device. iOS does not enforce scheme exclusivity — a malicious app can register the same scheme and intercept deep links intended for the legitimate app. The `application:openURL:options:` handler receives the full URL and any parameters; without validation of the calling app or URL content, this is an unauthenticated code execution vector. Universal Links (HTTPS-based) are significantly harder to hijack because they are validated by the Apple CDN against the app's apple-app-site-association file.

**References:** CWE-939, OWASP Mobile M1:2024

### Mandatory Rules

- **Validate `UIApplicationOpenURLOptionsSourceApplicationKey`** in `application:openURL:options:` — reject URLs from unknown source applications when sensitive operations are triggered.
- **Prefer Universal Links over custom URL schemes** for all deep linking — Universal Links are cryptographically tied to your domain and cannot be hijacked by another app.
- **Validate all parameters extracted from deep link URLs against an allowlist** — treat URL parameters as untrusted user input; do not pass them unvalidated to navigation, authentication, or database operations.
- **Use `openURL:options:completionHandler:` instead of the deprecated `openURL:`** — the newer API supports `UIApplicationOpenExternalURLOptionsKey` to validate the URL before opening.

```objc
// ❌ INSECURE — no validation of source app or URL contents; any app can trigger this
- (BOOL)application:(UIApplication *)app openURL:(NSURL *)url options:(NSDictionary *)options {
    NSString *token = [[url queryItems] valueForKey:@"token"];
    [self authenticateWithToken:token];  // malicious app sends forged token
    return YES;
}

// ✅ SECURE — validates source application and URL components before acting
- (BOOL)application:(UIApplication *)app openURL:(NSURL *)url options:(NSDictionary *)options {
    NSString *sourceApp = options[UIApplicationOpenURLOptionsSourceApplicationKey];
    NSSet *trustedApps = [NSSet setWithObjects:@"com.example.trusted-partner", nil];

    if (sourceApp && ![trustedApps containsObject:sourceApp]) {
        NSLog(@"[Security] Rejected deep link from untrusted app: %@", sourceApp);
        return NO;
    }

    NSURLComponents *components = [NSURLComponents componentsWithURL:url resolvingAgainstBaseURL:NO];
    NSString *action = nil;
    for (NSURLQueryItem *item in components.queryItems) {
        if ([item.name isEqualToString:@"action"]) { action = item.value; }
    }

    NSSet *allowedActions = [NSSet setWithObjects:@"view", @"share", nil];
    if (!action || ![allowedActions containsObject:action]) { return NO; }

    [self handleAction:action];
    return YES;
}
```

---

## 12. Cryptography Misuse

**Vulnerability:** CommonCrypto (`CCCrypt`) exposes direct access to many cipher suites including broken algorithms (DES, 3DES, RC4) and insecure modes (ECB). `CC_MD5` and `CC_SHA1` are present and deprecated but still compile without warnings in many SDK versions. `arc4random()` is a PRNG seeded from the kernel and is suitable for randomization but not for cryptographic key material — use `SecRandomCopyBytes` instead. Hardcoded encryption keys are trivially extracted from the binary with `strings` or a disassembler. IV reuse in AES-CBC leaks plaintext relationships.

**References:** CWE-327, CWE-328, CWE-338, CWE-321

### Mandatory Rules

- **Never use `kCCAlgorithmDES`, `kCCAlgorithm3DES`, or `kCCAlgorithmRC4`** — use `kCCAlgorithmAES` with `kCCModeCTR` or prefer the CryptoKit framework for AES-GCM.
- **Never use `kCCOptionECBMode`** — ECB mode reveals block patterns in ciphertext; use CBC with a random IV, or prefer authenticated encryption (GCM).
- **Generate IVs with `SecRandomCopyBytes`** — generate a fresh 16-byte IV for every encryption operation; never hardcode or reuse IVs.
- **Never use `CC_MD5`, `CC_SHA1`** for security purposes — use `CC_SHA256` minimum, or `CC_SHA3_256`.
- **Never hardcode symmetric keys in source code** — derive keys from user passphrases via PBKDF2 (`CCKeyDerivationPBKDF`) or retrieve from the Keychain.
- **Use `SecRandomCopyBytes` for all cryptographic random values** — `arc4random` is not a CSPRNG for key material generation.

```objc
// ❌ INSECURE — DES with ECB mode; key hardcoded in source; weak IV
uint8_t key[] = "mysecret";  // hardcoded 8-byte DES key
uint8_t iv[]  = {0};         // zero IV reused every time
size_t outLen;
CCCrypt(kCCEncrypt, kCCAlgorithmDES, kCCOptionECBMode,
        key, kCCKeySizeDES, iv,
        plaintext, plaintextLen,
        ciphertext, ciphertextLen, &outLen);

// ✅ SECURE — AES-256 with random IV; key from Keychain; use CryptoKit in Swift/ObjC bridged code
// For pure ObjC, use AES-CBC with a SecRandomCopyBytes IV:
uint8_t iv[kCCBlockSizeAES128];
SecRandomCopyBytes(kSecRandomDefault, sizeof(iv), iv);

// Retrieve key from Keychain (not hardcoded)
NSData *keyData = [self retrieveEncryptionKeyFromKeychain];
uint8_t *keyBytes = (uint8_t *)[keyData bytes];

size_t outLen = 0;
uint8_t *ciphertext = malloc(plaintextLen + kCCBlockSizeAES128);
CCCrypt(kCCEncrypt, kCCAlgorithmAES, kCCOptionPKCS7Padding,
        keyBytes, kCCKeySizeAES256, iv,
        plaintext, plaintextLen,
        ciphertext, plaintextLen + kCCBlockSizeAES128, &outLen);
// Prepend IV to ciphertext for storage/transmission
```

---

## 13. LocalAuthentication Bypass

**Vulnerability:** `LAContext evaluatePolicy:localizedReason:reply:` provides a boolean result in a callback. This boolean is the only control-flow gating the protected operation. Frida can trivially hook `objc_msgSend` and intercept the reply block, replacing `NO` with `YES` (or vice versa) at runtime, bypassing biometric authentication entirely. The correct approach is to use the Keychain to store a secret that is cryptographically protected by biometric enrollment — `kSecAccessControlBiometryCurrentSet` ensures the item is accessible only after a successful biometric evaluation by the Secure Enclave, which cannot be Frida-hooked.

**References:** CWE-287, CWE-290, OWASP MASVS MSTG-AUTH-8

### Mandatory Rules

- **Never gate security-sensitive operations solely on the `BOOL success` result of `evaluatePolicy:reply:`** — this value is hooker-bypassable.
- **Store the protected secret as a Keychain item with `kSecAccessControlBiometryCurrentSet`** — access the secret via `SecItemCopyMatching`; successful retrieval proves the Secure Enclave verified the biometric.
- **Use `kSecAccessControlBiometryCurrentSet` (not `kSecAccessControlBiometryAny`)** — `CurrentSet` invalidates the item if new biometrics are enrolled, preventing attackers from adding a fingerprint to gain access.
- **Pair biometric unlock with `kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly`** — requires the device to have a passcode; item is deleted if the passcode is removed.

```objc
// ❌ INSECURE — boolean result is Frida-hookable; auth bypass in one line
LAContext *context = [[LAContext alloc] init];
[context evaluatePolicy:LAPolicyDeviceOwnerAuthenticationWithBiometrics
        localizedReason:@"Confirm your identity"
                  reply:^(BOOL success, NSError *error) {
    if (success) {
        // This branch is reachable by hooking the reply block
        [self unlockVault];
    }
}];

// ✅ SECURE — secret protected by Secure Enclave biometric; SecItemCopyMatching proves auth
CFErrorRef cfError = NULL;
SecAccessControlRef acl = SecAccessControlCreateWithFlags(
    kCFAllocatorDefault,
    kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly,
    kSecAccessControlBiometryCurrentSet,
    &cfError
);

LAContext *context = [[LAContext alloc] init];
context.localizedReason = @"Confirm your identity to unlock the vault";

NSDictionary *query = @{
    (__bridge id)kSecClass:            (__bridge id)kSecClassGenericPassword,
    (__bridge id)kSecAttrService:      @"com.example.vault",
    (__bridge id)kSecAttrAccount:      @"vault_key",
    (__bridge id)kSecMatchLimit:       (__bridge id)kSecMatchLimitOne,
    (__bridge id)kSecReturnData:       @YES,
    (__bridge id)kSecUseAuthenticationContext: context,
};
CFTypeRef result = NULL;
OSStatus status = SecItemCopyMatching((__bridge CFDictionaryRef)query, &result);
if (status == errSecSuccess && result) {
    NSData *vaultKey = (__bridge_transfer NSData *)result;
    [self unlockVaultWithKey:vaultKey];  // crypto proves biometric was verified by Secure Enclave
}
```

---

## 14. Logging Sensitive Data

**Vulnerability:** `NSLog` writes to the device's unified logging system (accessible via `idevicesyslog`, Console.app, and Xcode's console). Unlike Android's `logcat`, iOS log output is not cleared between app launches and can persist across reboots. On older OS versions and jailbroken devices, any app with the `com.apple.diagnosticd.diagnostic` entitlement can read another app's log output. Credentials, tokens, PII, and private keys logged for debugging purposes are routinely captured in crash reports, analytics SDKs, MDM tools, and developer proxies.

**References:** CWE-532, CWE-312, OWASP MASVS MSTG-STORAGE-3

### Mandatory Rules

- **Never log authentication tokens, passwords, session cookies, cryptographic keys, or personal data with `NSLog`** — in any build configuration.
- **Wrap all debug-only logging in `#ifdef DEBUG` / `#endif` guards** — this ensures debug output is compiled out of Release builds entirely.
- **Use `os_log` with `%{private}` format specifiers for any app data logged in production** — the `private` annotation redacts the value from the public log on non-development devices.
- **Audit third-party SDK initialization for logging hooks** — analytics, crash reporting, and network debugging SDKs often log request bodies and responses.

```objc
// ❌ INSECURE — credentials and tokens logged unconditionally; visible in Console.app
- (void)loginSuccess:(NSDictionary *)response {
    NSLog(@"Login successful. Token: %@, User: %@, Password: %@",
          response[@"token"], response[@"username"], response[@"password"]);
}

// ✅ SECURE — sensitive values never logged; debug logging gated on DEBUG flag
- (void)loginSuccess:(NSDictionary *)response {
#ifdef DEBUG
    NSLog(@"[Auth] Login successful for user: %@", response[@"username"]);
    // Do NOT log token or password even in debug
#endif
    // Use os_log with private annotation for production diagnostics
    os_log_info(OS_LOG_DEFAULT, "Login completed for account type: %{public}@",
                response[@"accountType"]);
}
```

---

## 15. Memory Safety with Core Foundation and ARC Bridging

**Vulnerability:** ARC manages Objective-C object lifetimes automatically, but Core Foundation (CF) objects use manual reference counting via `CFRetain`/`CFRelease`. Bridging between CF and ObjC requires explicit ownership transfer annotations: `__bridge` (no transfer), `__bridge_transfer` (CF releases to ARC), `__bridge_retained` (ARC retains, caller must CFRelease). Using the wrong annotation causes double-free (crash, heap corruption) or memory leaks. `CFRelease(NULL)` crashes; `__unsafe_unretained` stores dangling pointers when the referent is deallocated. These bugs can become exploitable use-after-free conditions when an attacker can trigger specific allocation/deallocation sequences.

**References:** CWE-415, CWE-416, CWE-401, SEI CERT C MEM30-C

### Mandatory Rules

- **Use `__bridge_transfer` when ARC should take ownership of a CF object** — the CF object's retain count is consumed; do not call `CFRelease` afterward.
- **Use `__bridge_retained` when passing an ObjC object to a CF API that expects ownership** — you are responsible for calling `CFRelease` when done.
- **Always NULL-check CF results before calling `CFRelease`** — `CFRelease(NULL)` is undefined behavior and crashes on most platforms.
- **Avoid `__unsafe_unretained`** — use `__weak` instead; `__unsafe_unretained` becomes a dangling pointer when the referent is deallocated; `__weak` is automatically zeroed.

```objc
// ❌ INSECURE — bridge mistake causes double-free: ARC releases the ObjC object,
//               then the explicit CFRelease frees it again
CFStringRef cfStr = CFStringCreateWithCString(NULL, cStr, kCFStringEncodingUTF8);
NSString *nsStr = (__bridge NSString *)cfStr;  // should be __bridge_transfer
// ... use nsStr ...
CFRelease(cfStr);  // double-free: ARC already released nsStr / cfStr

// ✅ SECURE — __bridge_transfer transfers ownership to ARC; no manual CFRelease needed
CFStringRef cfStr = CFStringCreateWithCString(NULL, cStr, kCFStringEncodingUTF8);
NSString *nsStr = (__bridge_transfer NSString *)cfStr;  // ARC owns it now
// ... use nsStr; no CFRelease call needed
```

```objc
// ❌ INSECURE — __unsafe_unretained delegate becomes dangling pointer after dealloc
@property (nonatomic, unsafe_unretained) id<MyDelegate> delegate;  // dangling if delegate is released

// ✅ SECURE — __weak zeroed automatically when referent is deallocated
@property (nonatomic, weak) id<MyDelegate> delegate;
```

---

## 16. NSXMLParser XXE

**Vulnerability:** `NSXMLParser` is SAX-based and does not expand external entities by default, making it safe for most uses. However, code that uses `libxml2` directly (common in legacy networking and SOAP integrations) with the `XML_PARSE_NOENT` or `LIBXML_DTDLOAD` options enabled will expand `SYSTEM` external entity references, enabling XXE — reading arbitrary local files, SSRF to internal services, or denial of service via entity expansion ("billion laughs"). `initWithContentsOfURL:` with an attacker-controlled XML source can redirect to a malicious DTD.

**References:** CWE-611, CWE-776

### Mandatory Rules

- **Do not initialize `NSXMLParser` with `initWithContentsOfURL:` using untrusted URLs** — download the XML first with `NSURLSession` (applying network security checks), then initialize with `initWithData:`.
- **When using `libxml2` directly, never pass `XML_PARSE_NOENT` or `XML_PARSE_DTDLOAD`** — these flags enable external entity and DTD loading; omit them explicitly.
- **Call `xmlCtxtUseOptions` to suppress DTD loading and entity expansion** — set `XML_PARSE_NONET | XML_PARSE_NOENT` negated (i.e., use 0 or `XML_PARSE_COMPACT` only).

```objc
// ❌ INSECURE — libxml2 with NOENT and DTDLOAD; XXE reads /etc/passwd or internal files
xmlDocPtr doc = xmlReadMemory([xmlData bytes], (int)[xmlData length],
                              "noname.xml", NULL,
                              XML_PARSE_NOENT | XML_PARSE_DTDLOAD);  // XXE enabled

// ✅ SECURE — libxml2 without entity expansion or DTD loading
xmlDocPtr doc = xmlReadMemory([xmlData bytes], (int)[xmlData length],
                              "noname.xml", NULL,
                              XML_PARSE_NONET);  // network fetch disabled; no entity expansion
if (doc == NULL) {
    // parsing failed; log and return
    return;
}
// process doc; xmlFreeDoc(doc) when done
```

```objc
// ✅ SECURE — NSXMLParser is safe by default; do not use initWithContentsOfURL: with untrusted input
NSURLSession *session = [NSURLSession sharedSession];
NSURLSessionDataTask *task = [session dataTaskWithURL:trustedURL
                                    completionHandler:^(NSData *data, NSURLResponse *response, NSError *error) {
    if (!error && data) {
        NSXMLParser *parser = [[NSXMLParser alloc] initWithData:data];  // safe: data, not URL
        parser.delegate = self;
        [parser parse];
    }
}];
[task resume];
```

---

## 17. Binary Hardening and Entitlements

**Vulnerability:** Without position-independent executable (PIE) enabled, the binary is loaded at a fixed address, making ROP/JOP chain construction trivial. Without stack canaries, stack overflows do not trigger `__stack_chk_fail`. The `get-task-allow` entitlement enables debugger attachment in production builds — used legitimately during development, but when left enabled in an App Store binary, it allows `lldb` or Frida to attach and inspect memory. `com.apple.security.cs.allow-unsigned-executable-memory` permits `mmap(MAP_JIT)` without code signature checks, enabling unsigned code injection on macOS.

**References:** CWE-693, CWE-119

### Mandatory Rules

- **Enable PIE** — pass `-pie` to the linker; verify with `otool -hv <binary> | grep PIE`.
- **Enable stack canaries** — set `OTHER_CFLAGS = -fstack-protector-strong` in Build Settings; verify with `nm <binary> | grep stack_chk`.
- **Set `get-task-allow: false` in the production entitlements file** — use separate Development.entitlements (with `true`) and Release.entitlements (with `false`) in your Xcode configuration.
- **Do not include `com.apple.security.cs.allow-unsigned-executable-memory` in production entitlements** unless your app explicitly requires a JIT (e.g., a JavaScript engine).
- **Enable ARC** — set `CLANG_ENABLE_OBJC_ARC = YES` in Build Settings; verify with `otool -l <binary> | grep __objc_arc`.

```bash
# ✅ Verify PIE is enabled on the shipped binary
otool -hv MyApp.app/MyApp | grep PIE
# Expected output: PIE

# ✅ Verify stack canary symbol is present
nm MyApp.app/MyApp | grep __stack_chk_fail
# Expected output: U ___stack_chk_fail

# ✅ Verify production entitlement: get-task-allow must be false
codesign -d --entitlements - MyApp.app | grep -A1 get-task-allow
# Expected output: <key>get-task-allow</key><false/>

# ✅ Inspect all entitlements for unexpected privileges
codesign -d --entitlements - MyApp.app
```

---

## 18. CocoaPods and Supply Chain

**Vulnerability:** CVE-2023-38894 disclosed that the CocoaPods trunk server contained an account takeover vulnerability allowing any actor to claim orphaned pod owner accounts (those using old email domains) and replace pod source archives with malicious versions — affecting an estimated 3 million iOS and macOS applications. Pods without version pins in the Podfile allow `pod update` to silently pull a newer, potentially compromised version. Pod archives are not code-signed by Apple's notarization process, so malicious code in a pod is not blocked by Gatekeeper.

**References:** CVE-2023-38894, CWE-494, OWASP A06:2021

### Mandatory Rules

- **Commit `Podfile.lock` to version control** — this locks the exact pod version and source checksum; review diffs on every `pod update`.
- **Pin exact versions in Podfile** — use `pod 'Alamofire', '5.8.1'` not `~>5.0` or `>= 5`; floating version constraints allow silent upgrades to compromised versions.
- **Verify pod checksums after installation** — `pod install --verbose` prints SHA hashes; compare against known-good values from the pod author's GitHub release.
- **Prefer Swift Package Manager** for new dependencies — SPM uses content-addressed package resolution with `Package.resolved` and is integrated into Xcode's notarization flow.
- **Audit all new pods before adding** — review the pod's GitHub repository, recent commit history, and ownership; prefer pods with > 1 active maintainer and recent CI badges.

```ruby
# ❌ INSECURE — floating version constraints; pod update pulls any new version silently
pod 'Alamofire', '~> 5.0'
pod 'SDWebImage'          # no version pin at all

# ✅ SECURE — exact version pins; Podfile.lock committed and reviewed on every update
pod 'Alamofire',  '5.8.1'
pod 'SDWebImage', '5.19.2'
```

---

## 19. Jailbreak and Tampering Detection

**Vulnerability:** Jailbroken devices disable key iOS security controls: code signing enforcement is removed (allowing unsigned binaries and dylib injection), the sandbox is weakened (apps can access other apps' data directories), and the Secure Enclave may be partially bypassed by kernel exploits. Apps that perform sensitive operations (banking, DRM, enterprise MDM) should detect jailbreaks and tampering as a defense-in-depth layer, not as a primary security control — all jailbreak detection can eventually be bypassed by a sufficiently motivated attacker using Frida or Shadow/Liberty Lite.

**References:** OWASP MASVS MSTG-RESILIENCE-1, MSTG-RESILIENCE-4

### Mandatory Rules

- **Implement multiple independent detection vectors** — file existence, URL scheme checks, symbolic link detection, and dylib injection checks; a single check is easily bypassed.
- **React to detection with soft degradation, not hard crash** — log the event server-side, disable sensitive features, and prompt the user; crashing on detection is easily bypassed by patching the branch.
- **Do not rely solely on jailbreak detection for security** — enforce security server-side; treat jailbreak detection as threat intelligence, not a security gate.
- **Verify binary integrity at runtime** — check the code signature with `SecStaticCodeCreateWithPath` and `SecCodeCheckValidity`.

```objc
// ✅ Defense-in-depth jailbreak detection (bypassable; layer with server-side controls)
- (BOOL)isDeviceJailbroken {
    // Check 1: Cydia and common jailbreak file paths
    NSArray *jailbreakPaths = @[
        @"/Applications/Cydia.app",
        @"/Library/MobileSubstrate/MobileSubstrate.dylib",
        @"/bin/bash",
        @"/usr/sbin/sshd",
        @"/etc/apt",
        @"/private/var/lib/apt/",
    ];
    for (NSString *path in jailbreakPaths) {
        if ([[NSFileManager defaultManager] fileExistsAtPath:path]) { return YES; }
    }

    // Check 2: Sandbox escape — write outside sandbox
    NSError *error;
    NSString *testPath = @"/private/jailbreak_test.txt";
    [@"test" writeToFile:testPath atomically:YES encoding:NSUTF8StringEncoding error:&error];
    if (!error) {
        [[NSFileManager defaultManager] removeItemAtPath:testPath error:nil];
        return YES;
    }

    // Check 3: Injected dylibs (unexpected frameworks loaded into process)
    int imageCount = _dyld_image_count();
    for (int i = 0; i < imageCount; i++) {
        const char *imageName = _dyld_get_image_name(i);
        if (strstr(imageName, "MobileSubstrate") || strstr(imageName, "cynject")) {
            return YES;
        }
    }

    return NO;
}
```

---

## 20. Info.plist Security Misconfigurations

**Vulnerability:** Info.plist controls numerous security-relevant behaviors: App Transport Security (ATS), file sharing exposure, background execution modes, and exported URL schemes. `NSAllowsArbitraryLoads: YES` disables ATS for all connections globally, removing TLS enforcement. `UIFileSharingEnabled: YES` exposes the entire Documents/ directory via iTunes File Sharing and the Files app, making any file stored there user-accessible and potentially leaked. Overly broad `UIBackgroundModes` allow continued execution that can be abused for tracking or battery drain.

**References:** CWE-16, OWASP MASVS MSTG-NETWORK-2

### Mandatory Rules

- **Never set `NSAllowsArbitraryLoads: YES` in production** — if a third-party SDK requires it, update the SDK or submit a targeted `NSExceptionDomains` entry scoped to that domain only.
- **Do not set `UIFileSharingEnabled: YES` unless the app's core function is file sharing** — any file in Documents/ becomes user-accessible via the Files app and iTunes.
- **Declare only necessary `UIBackgroundModes`** — each mode must be justified; App Store review will reject unjustified background mode declarations.
- **Review CFBundleURLSchemes** — remove unused URL schemes; each registered scheme is an attack surface for deep link hijacking.

```xml
<!-- ❌ INSECURE — ATS globally disabled; arbitrary plaintext HTTP allowed; file sharing on -->
<key>NSAppTransportSecurity</key>
<dict>
    <key>NSAllowsArbitraryLoads</key>
    <true/>
</dict>
<key>UIFileSharingEnabled</key>
<true/>
<key>UIBackgroundModes</key>
<array>
    <string>fetch</string>
    <string>processing</string>
    <string>voip</string>
    <string>location</string>
    <string>audio</string>
</array>

<!-- ✅ SECURE — ATS enabled globally; per-domain exception only for legacy partner API;
                 file sharing disabled; background modes minimal and justified -->
<key>NSAppTransportSecurity</key>
<dict>
    <key>NSExceptionDomains</key>
    <dict>
        <key>legacy-partner-api.example.com</key>
        <dict>
            <key>NSExceptionAllowsInsecureHTTPLoads</key>
            <true/>
            <key>NSExceptionMinimumTLSVersion</key>
            <string>TLSv1.2</string>
        </dict>
    </dict>
</dict>
<!-- UIFileSharingEnabled key omitted (defaults to false) -->
<key>UIBackgroundModes</key>
<array>
    <string>fetch</string>  <!-- required for content refresh -->
</array>
```

---

## CVE Reference Table

| CVE | Severity | Component | Description | Fixed In |
|-----|----------|-----------|-------------|----------|
| CVE-2019-8641 | Critical (9.8) | NSKeyedUnarchiver (iOS/macOS) | Out-of-bounds read in NSKeyedUnarchiver enabling remote code execution via maliciously crafted serialized data; exploited to achieve kernel-level access in targeted attacks | iOS 12.4.1, macOS 10.14.6 Supplemental |
| CVE-2022-22620 | Critical (8.8) | WebKit (Safari/WKWebView) | Use-after-free in WebKit's legacy form handling; exploited in-the-wild for remote code execution; affected apps embedding WKWebView on iOS ≤ 15.3 | iOS 15.3.1, macOS 12.2.1 |
| CVE-2023-41993 | Critical (8.8) | WebKit (Safari/WKWebView) | Type confusion in JIT compiler leading to arbitrary code execution; exploited in-the-wild against iOS < 16.7.1; used in Predator spyware delivery chain | iOS 17.0.1, iOS 16.7.1, macOS 14.0 |
| CVE-2023-38894 | High (9.8 CVSS on trunk server) | CocoaPods Trunk Server | Account takeover via email domain expiry; attacker could claim ownership of orphaned CocoaPods accounts and push malicious pod versions; estimated 3 million apps affected | CocoaPods trunk patched May 2023 |
| CVE-2023-32434 | Critical (7.8) | iOS Kernel (XNU) | Integer overflow in XNU's memory subsystem exploited in Operation Triangulation; enabled kernel memory read/write from WebKit renderer process; chained with CVE-2023-32435 | iOS 15.7.7, iOS 16.5.1 |
| CVE-2023-32435 | Critical (8.8) | WebKit (iOS) | Memory corruption in WebKit's JavaScript engine; initial code execution stage in Operation Triangulation zero-click exploit chain targeting iMessage; no user interaction required | iOS 15.7.7, iOS 16.5.1 |
| CVE-2021-30900 | High (7.8) | AGXAccelerator (GPU driver) | Out-of-bounds write in Apple's GPU kernel extension; exploited by unc0ver jailbreak tool to gain kernel code execution from a sandboxed app on iOS 14.x | iOS 15.0 |
| CVE-2020-9859 | High (7.0) | kernel / mach_vm (iOS) | Race condition in `memory_entry` Mach trap; exploited by unc0ver jailbreak for kernel privilege escalation from sandboxed app; no user interaction required | iOS 13.5.1 |

---

## Security Checklist

### Data Storage
- [ ] No authentication tokens, passwords, or session cookies stored in `NSUserDefaults`
- [ ] No sensitive data written to the Documents/ directory without explicit purpose
- [ ] All files containing sensitive data created with `NSFileProtectionComplete` attribute
- [ ] Keychain items use `kSecAttrAccessibleWhenUnlockedThisDeviceOnly` or stricter
- [ ] `kSecAttrAccessibleAlways` and `kSecAttrAccessibleAlwaysThisDeviceOnly` are absent from all Keychain queries
- [ ] No sensitive data written to temporary files (`/tmp`, `NSTemporaryDirectory()`) without cleanup
- [ ] SQLite databases containing sensitive data have `NSFileProtectionComplete` attribute set
- [ ] No PII or secrets present in any `.plist` file bundled with the app
- [ ] Application Support directory used (not Documents/) for user-generated private data
- [ ] Core Data persistent stores encrypted via SQLite cipher or file protection attribute

### Network Security
- [ ] `NSAllowsArbitraryLoads: YES` absent from all Info.plist configurations (including test schemes)
- [ ] Per-domain ATS exceptions are documented and limited to the minimum necessary scope
- [ ] `didReceiveAuthenticationChallenge:` calls `SecTrustEvaluateWithError` before accepting
- [ ] Certificate pinning implemented for all first-party API endpoints
- [ ] SPKI hash pinning preferred over leaf certificate pinning for resilience to cert rotation
- [ ] All HTTP connections use HTTPS; no plaintext HTTP in production
- [ ] TLS 1.0 and 1.1 disabled via ATS configuration
- [ ] Timeout set on all `NSURLSession` data tasks and background sessions
- [ ] `UIApplicationOpenURLOptionsSourceApplicationKey` validated in all deep link handlers
- [ ] Universal Links implemented and preferred over custom URL schemes for sensitive operations

### Cryptography
- [ ] No use of `CC_MD5`, `CC_SHA1`, `kCCAlgorithmDES`, `kCCAlgorithm3DES`, `kCCAlgorithmRC4`
- [ ] `kCCOptionECBMode` absent from all `CCCrypt` calls
- [ ] All IVs generated with `SecRandomCopyBytes` immediately before each encryption operation
- [ ] No hardcoded symmetric keys, passwords, or seeds in source code, headers, or plist files
- [ ] Keys stored in Keychain, never in `NSUserDefaults`, files, or source code
- [ ] `SecRandomCopyBytes` used for all cryptographic random values (not `arc4random`, `rand`, `random`)
- [ ] PBKDF2 (`CCKeyDerivationPBKDF`) or Argon2 used for password-derived keys; minimum 100,000 iterations
- [ ] Encrypted data includes authentication tag or HMAC to detect tampering
- [ ] CryptoKit or libsodium preferred over raw CommonCrypto for new code

### Runtime Security
- [ ] No user-controlled strings passed to `NSLog`, `NSString stringWithFormat:`, or `NSException raise:format:` as the format argument
- [ ] `NSKeyedUnarchiver` calls use `requiresSecureCoding = YES` and explicit `allowedClasses`
- [ ] `[NSKeyedUnarchiver unarchiveObjectWithData:]` absent from codebase
- [ ] No user input passed to `setValue:forKeyPath:`, `valueForKeyPath:`, or `valueForKey:` without allowlist validation
- [ ] No user input passed to `NSClassFromString`, `NSSelectorFromString`, or `performSelector:`
- [ ] KVC key paths validated against explicit `NSSet` or `NSArray` of permitted keys before use
- [ ] `NSPredicate` format strings use `%@` and `%K` placeholders; never concatenated user input
- [ ] `WKWebView` `evaluateJavaScript:` calls use JSON-encoded values; never raw user input
- [ ] `UIWebView` absent from codebase (replaced with WKWebView)
- [ ] Biometric-protected secrets stored in Keychain with `kSecAccessControlBiometryCurrentSet`; `LAContext` boolean alone never gates security-critical actions
- [ ] libxml2 calls do not include `XML_PARSE_NOENT` or `XML_PARSE_DTDLOAD` flags
- [ ] `jailbreak detection implemented as defense-in-depth; critical security controls enforced server-side

### Binary Protections
- [ ] PIE enabled (`-pie` linker flag); verified with `otool -hv | grep PIE`
- [ ] Stack canaries enabled (`-fstack-protector-strong`); verified with `nm | grep stack_chk`
- [ ] ARC enabled for all Objective-C compilation units (`CLANG_ENABLE_OBJC_ARC = YES`)
- [ ] `get-task-allow: false` in Release entitlements (separate from Debug entitlements)
- [ ] `com.apple.security.cs.allow-unsigned-executable-memory` absent from production entitlements
- [ ] No `strcpy`, `strcat`, `sprintf`, `gets` in codebase (`grep` or clang analyzer confirmed)
- [ ] `__unsafe_unretained` absent or replaced with `__weak`
- [ ] Xcode Static Analyzer run clean with no analyzer warnings in the security category
- [ ] Bitcode disabled for final production builds (prevents post-compilation binary modification)
- [ ] Strip debug symbols in Release builds (`STRIP_INSTALLED_PRODUCT = YES`)

### Supply Chain
- [ ] `Podfile.lock` committed to version control and reviewed on every `pod update`
- [ ] All CocoaPods pinned to exact versions (no `~>` or open version constraints)
- [ ] New pods reviewed for active maintenance, contributor count, and recent commit history
- [ ] Pod checksums verified post-install (`pod install --verbose`)
- [ ] Swift Package Manager `Package.resolved` committed and reviewed on every dependency update
- [ ] No pods or SPM packages from unverified private spec repos without documented approval
- [ ] OSV Scanner or `osv-scanner --lockfile Podfile.lock` run in CI

---

## Tooling

| Tool | Purpose | Command / Usage |
|------|---------|-----------------|
| [Xcode Static Analyzer](https://developer.apple.com/documentation/xcode/improving-your-app-s-performance) | Detects memory errors, use-after-free, null dereference, CF object leaks, and format string misuse at compile time | `xcodebuild -scheme MyApp analyze` or **Product → Analyze** in Xcode IDE |
| [MobSF (Mobile Security Framework)](https://github.com/MobSF/Mobile-Security-Framework-MobSF) | Automated static and dynamic analysis of iOS IPA: checks ATS config, Info.plist misconfigurations, insecure API usage, hardcoded secrets, and weak crypto | `docker run -it --rm -p 8000:8000 opensecurity/mobile-security-framework-mobsf`; upload IPA via web UI |
| [objection](https://github.com/sensepost/objection) | Frida-based runtime exploration: dumps Keychain, bypasses SSL pinning, lists loaded classes, hooks methods, explores the filesystem from a running app | `objection -g "MyApp" explore`; `ios keychain dump`; `ios sslpinning disable` |
| [Frida](https://frida.re) | Dynamic instrumentation: intercepts Objective-C method calls at runtime, modifies return values, traces argument values, patches memory | `frida -U -n MyApp -l hook_script.js`; `frida-trace -U -m "-[NSURLSession *]" MyApp` |
| [class-dump](https://github.com/nygard/class-dump) / [dsdump](https://github.com/DerekSelander/dsdump) | Extracts Objective-C class interfaces and protocols from a compiled binary; reveals private APIs and method signatures | `class-dump -H MyApp.app/MyApp -o headers/`; `dsdump --objc MyApp.app/MyApp` |
| [Hopper Disassembler](https://www.hopperapp.com) | Interactive disassembler and decompiler for ARM64; generates pseudo-code from binary, identifies Objective-C message sends and string literals | Open binary in Hopper GUI; use **File → Produce Pseudo-code File** for bulk decompilation |
| [otool](https://www.unix.com/man-page/osx/1/otool/) / [nm](https://www.unix.com/man-page/osx/1/nm/) | Inspect Mach-O binary headers, linked libraries, symbols, and load commands; verify PIE, stack canaries, and linked frameworks | `otool -hv MyApp | grep PIE`; `otool -L MyApp`; `nm MyApp | grep stack_chk` |
| [codesign](https://developer.apple.com/library/archive/documentation/Security/Conceptual/CodeSigningGuide/) | Inspect and verify code signatures, entitlements, and provisioning profiles; check `get-task-allow` and dangerous entitlements | `codesign -d --entitlements - MyApp.app`; `codesign -v -v MyApp.app` |
| [idevicesyslog](https://github.com/libimobiledevice/libimobiledevice) | Stream device syslog to terminal; captures all `NSLog` output from installed apps for log-content auditing | `idevicesyslog -u <UDID> | grep MyApp` |
| [needle](https://github.com/WithSecureLabs/needle) | iOS security assessment framework: automates checks for insecure data storage, Keychain misuse, binary protections, and inter-process communication | `python needle.py`; modules: `storage/coredata/`, `binary/metadata/`, `network/` |
| [cocoapods-keys](https://github.com/orta/cocoapods-keys) | CocoaPods plugin that stores sensitive keys outside source code; generates obfuscated Objective-C accessors at build time | `gem install cocoapods-keys`; add `plugin 'cocoapods-keys', keys: { 'APIKey' => 'MyAPIKey' }` to Podfile |
| [OSV Scanner](https://github.com/google/osv-scanner) | Scans `Podfile.lock` and `Package.resolved` against the OSV vulnerability database for known CVEs in dependencies | `osv-scanner --lockfile Podfile.lock`; `osv-scanner --lockfile Package.resolved` |
