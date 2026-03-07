# Dart / Flutter Security Rules

> **Standard:** Security rules for Dart 3.x and Flutter applications, covering mobile (Android/iOS), web, and server-side Dart. Addresses language-specific pitfalls, Flutter framework patterns, and OWASP Mobile Top 10:2024.
> **Sources:** OWASP Mobile Top 10:2024, OWASP MASVS, Dart SDK Security Advisories, NVD/CVE Database, GitHub Advisory Database (pub.dev), Zellic Research, NVISO Labs, Cossack Labs Flutter Security, Google Android Security
> **Version:** 1.0.0
> **Last updated:** March 2026
> **Scope:** Dart 3.x SDK and Flutter 3.x framework. Covers mobile (Android/iOS), Dart server (dart:io), and Flutter web. Does not cover Dart compiled to JavaScript beyond web-specific XSS notes.

---

## General Instructions

Apply these rules when writing or reviewing Dart or Flutter code. Dart is a memory-safe, garbage-collected language that eliminates entire classes of C/C++ vulnerabilities (buffer overflows, use-after-free). However, Dart and Flutter introduce their own high-value attack surface: insecure local storage is the most common critical finding in Flutter penetration tests, followed by TLS bypass via `badCertificateCallback`, weak PRNG usage (`dart:math Random`), and SQL injection in `sqflite`. Mobile apps are distributed as compiled binaries that attackers can reverse-engineer, making client-side secrets, hardcoded keys, and client-only validation especially dangerous. Always assume the device is untrusted.

---

## 1. Weak Pseudorandom Number Generation — `dart:math Random` vs `Random.secure()`

**Vulnerability:** `dart:math`'s default `Random()` is a pseudorandom number generator (PRNG) seeded with only 32 bits of entropy — the seed is truncated with `0xFFFFFFFF`, limiting the possible random streams to approximately 2³² (~4.3 billion). A desktop computer can exhaust the entire keyspace in roughly 16 minutes. Using `Random()` to generate tokens, session IDs, nonces, cryptographic keys, or recovery phrases produces predictable values that an attacker with knowledge of the seed window can brute-force. In 2024, Zellic Research found Proton Wallet's Flutter app used `Random()` to generate BIP39 mnemonic phrases and wallet encryption keys, making all wallets created with vulnerable versions recoverable by brute force.

**References:** CWE-338, CWE-330, Zellic Research — Proton Dart/Flutter CSPRNG vulnerability (2024)

### Mandatory Rules

- **Never use `dart:math` `Random()` for security-sensitive values** — tokens, session IDs, nonces, CSRF values, OTPs, password reset codes, encryption keys, or any value that must be unpredictable.
- **Always use `Random.secure()`** for cryptographic randomness — it delegates to the OS CSPRNG (`/dev/urandom` on Linux/macOS, `BCryptGenRandom` on Windows).
- **Use `dart:math`'s `Random()` only for non-security purposes** — shuffling UI elements, sampling telemetry, game mechanics.
- **When generating raw random bytes for keys, use `dart:typed_data` `Uint8List` filled via `Random.secure().nextInt(256)`** or use `package:cryptography`'s `SecretKeyData.random()`.

```dart
// ❌ INSECURE — PRNG with 32-bit entropy; predictable within 2^32 iterations
import 'dart:math';

String generateToken() {
  final random = Random();  // seeds from clock; only 32-bit seed space
  final bytes = List<int>.generate(32, (_) => random.nextInt(256));
  return bytes.map((b) => b.toRadixString(16).padLeft(2, '0')).join();
}

// ❌ INSECURE — time-seeded PRNG used for crypto key material
final key = List<int>.generate(32, (_) => Random(DateTime.now().millisecondsSinceEpoch).nextInt(256));

// ✅ SECURE — OS-backed CSPRNG; cryptographically unpredictable
import 'dart:math';
import 'dart:typed_data';

String generateToken() {
  final random = Random.secure();
  final bytes = Uint8List.fromList(
    List<int>.generate(32, (_) => random.nextInt(256)),
  );
  return bytes.map((b) => b.toRadixString(16).padLeft(2, '0')).join();
}

// ✅ SECURE — using package:cryptography for key generation
import 'package:cryptography/cryptography.dart';

final algorithm = AesGcm.with256bits();
final secretKey = await algorithm.newSecretKey();  // uses secure random internally
```

---

## 2. Insecure Local Storage — SharedPreferences and Hive Plaintext

**Vulnerability:** `shared_preferences` stores data as XML/plist files on disk with no encryption. On Android these files live in `/data/data/<package>/shared_prefs/` and are readable without root on many devices (backup-enabled apps, ADB backup on non-production builds, physical access). `NSUserDefaults` on iOS is similarly unencrypted. Storing secrets (tokens, passwords, PII, session cookies) here exposes them to: local device attackers, malicious apps on rooted devices, and ADB backup extraction. Hive boxes are also plaintext by default; even with encryption enabled, Hive stores the box *key* in plaintext in the frame header — only the value is encrypted.

**References:** CWE-312, CWE-922, OWASP MASVS-STORAGE-1, OWASP Mobile Top 10:2024 M9, GHSA-3hpf-ff72-j67p (shared_preferences_android deserialization, Dec 2024)

### Mandatory Rules

- **Never store secrets in `SharedPreferences`** — tokens, passwords, PII, encryption keys, session cookies. Use `flutter_secure_storage` instead.
- **Never store secrets in Hive without understanding that box keys are stored in plaintext** — even in an encrypted box, the key field is unencrypted; do not use sensitive identifiers (email, user ID) as Hive keys.
- **Use `flutter_secure_storage`** for all security-sensitive key-value data — it delegates to Android Keystore / iOS Keychain.
- **For encrypted Hive boxes, store the encryption key in `flutter_secure_storage`**, never hardcoded and never in `SharedPreferences`.
- **For encrypted SQLite, use `sqflite_sqlcipher`** with a key stored in the device keystore, not hardcoded.
- **Set `iCloudSync: false` and `accessibility: KeychainAccessibility.first_unlock_this_device` on iOS** when using `flutter_secure_storage` for highly sensitive data to prevent iCloud sync.
- **Deleted Hive entries are soft-deleted** — data persists in the file until compaction; call `box.compact()` after deleting sensitive entries.

```dart
// ❌ INSECURE — plaintext storage of auth token
import 'package:shared_preferences/shared_preferences.dart';

Future<void> saveToken(String token) async {
  final prefs = await SharedPreferences.getInstance();
  await prefs.setString('auth_token', token);  // stored unencrypted on disk
}

// ❌ INSECURE — Hive without encryption
import 'package:hive_flutter/hive_flutter.dart';

final box = await Hive.openBox('userBox');
await box.put('auth_token', token);  // plaintext file

// ✅ SECURE — flutter_secure_storage (Keystore/Keychain-backed)
import 'package:flutter_secure_storage/flutter_secure_storage.dart';

const _storage = FlutterSecureStorage(
  aOptions: AndroidOptions(encryptedSharedPreferences: true),
  iOptions: IOSOptions(accessibility: KeychainAccessibility.first_unlock_this_device),
);

Future<void> saveToken(String token) async {
  await _storage.write(key: 'auth_token', value: token);
}

Future<String?> readToken() async {
  return await _storage.read(key: 'auth_token');
}

// ✅ SECURE — encrypted Hive box with key stored in Keystore/Keychain
import 'package:hive_flutter/hive_flutter.dart';
import 'package:flutter_secure_storage/flutter_secure_storage.dart';
import 'dart:convert';

Future<Box> openSecureBox(String boxName) async {
  const secureStorage = FlutterSecureStorage();
  String? keyString = await secureStorage.read(key: '${boxName}_key');
  Uint8List encryptionKey;
  if (keyString == null) {
    encryptionKey = Hive.generateSecureKey();  // uses Random.secure() internally
    await secureStorage.write(key: '${boxName}_key', value: base64Encode(encryptionKey));
  } else {
    encryptionKey = base64Decode(keyString);
  }
  return Hive.openBox(boxName, encryptionCipher: HiveAesCipher(encryptionKey));
}
```

---

## 3. TLS Certificate Validation Bypass — `badCertificateCallback`

**Vulnerability:** `dart:io`'s `HttpClient.badCertificateCallback` is called when the server presents a certificate that fails validation (expired, self-signed, wrong hostname, untrusted CA). Returning `true` from this callback unconditionally accepts the certificate, silently downgrading TLS to plain cleartext from a security perspective — the connection is encrypted but the identity is unverified. This enables man-in-the-middle (MitM) attacks. This pattern is common in development but frequently shipped to production. Additionally, `CVE-2024-29887` (Serverpod ≤1.2.5) was caused by the same pattern in a server-side Dart package.

**References:** CWE-295, CVE-2022-0451 (Dart HttpClient cross-origin header leak, fixed Dart 2.16.0), CVE-2024-29887 (Serverpod TLS bypass), CVE-2024-48915 (Agent Dart improper cert verification)

### Mandatory Rules

- **Never return `true` unconditionally from `badCertificateCallback`** — not in debug, not in development, not behind a feature flag. Fix the underlying certificate problem instead.
- **Never disable certificate verification with `SecurityContext(withTrustedRoots: false)` without pinning a specific known-good certificate.**
- **For development against self-signed certs, use a properly configured dev CA** added to the OS trust store, not `badCertificateCallback = (_, __, ___) => true`.
- **Implement certificate pinning for high-value API endpoints** by loading the pinned certificate from assets and verifying it in the callback.
- **Drop sensitive HTTP headers on cross-origin redirects** — Dart SDK ≥2.16 does this automatically; ensure you are not on an older SDK.
- **Use `package:dio` ≥5.0.0** — earlier versions (≤4.x) contained a CRLF injection vulnerability (CVE-2021-31402) via unvalidated HTTP method strings.

```dart
// ❌ INSECURE — accepts all certificates including attacker-controlled ones
HttpClient createClient() {
  final client = HttpClient();
  client.badCertificateCallback = (X509Certificate cert, String host, int port) => true;
  return client;
}

// ❌ INSECURE — disables all root CAs with no pinning
final ctx = SecurityContext(withTrustedRoots: false);
final client = HttpClient(context: ctx);  // will accept any cert

// ✅ SECURE — strict certificate validation (default behavior; do not override)
HttpClient createClient() {
  return HttpClient();  // uses OS trust store by default — do not touch badCertificateCallback
}

// ✅ SECURE — certificate pinning: load known-good cert, reject everything else
import 'dart:io';
import 'package:flutter/services.dart';

Future<HttpClient> createPinnedClient() async {
  final certBytes = await rootBundle.load('assets/certs/api.example.com.pem');
  final ctx = SecurityContext(withTrustedRoots: false);
  ctx.setTrustedCertificatesBytes(certBytes.buffer.asInt8List());
  final client = HttpClient(context: ctx);
  client.badCertificateCallback = (cert, host, port) => false;  // reject mismatches
  return client;
}

// ✅ SECURE — using package:dio with certificate pinning
import 'package:dio/dio.dart';

Dio createPinnedDio() {
  final dio = Dio();
  (dio.httpClientAdapter as DefaultHttpClientAdapter).onHttpClientCreate = (client) {
    client.badCertificateCallback = (cert, host, port) => false;
    return client;
  };
  return dio;
}
```

---

## 4. SQL Injection in `sqflite`

**Vulnerability:** `sqflite`'s `rawQuery()` and `rawInsert()` methods accept raw SQL strings. Concatenating user input into these strings creates SQL injection vulnerabilities identical to backend SQL injection. Additionally, `flutter_downloader` ≤1.11.1 contained a CVE-2023-41387 SQL injection (CVSS 9.1 Critical) that allowed remote attackers to steal session tokens and overwrite arbitrary files via a malicious server response.

**References:** CWE-89, CVE-2023-41387 (flutter_downloader SQL injection, Critical 9.1, fixed 1.11.2)

### Mandatory Rules

- **Never concatenate user input into raw SQL strings** — use parameterized queries with `?` placeholders and the `whereArgs` parameter in all sqflite operations.
- **Use the high-level `query()`, `insert()`, `update()`, `delete()` helpers** instead of `rawQuery()`/`rawDelete()` wherever possible — they enforce parameterization.
- **When `rawQuery()` is necessary, always pass user values in the `arguments` list**, never via string interpolation.
- **Upgrade `flutter_downloader` to ≥1.11.2** if used; the ≤1.11.1 SQL injection is exploitable by a malicious server.
- **Encrypt the database file with `sqflite_sqlcipher`** when the database contains PII or sensitive application data.

```dart
// ❌ INSECURE — SQL injection via string interpolation
Future<List<Map<String, dynamic>>> getUserByName(String username) {
  return db.rawQuery("SELECT * FROM users WHERE name = '$username'");
  // Attacker input: ' OR '1'='1 → dumps entire table
}

// ❌ INSECURE — string concatenation in query helper
await db.query(
  'users',
  where: 'email = $userEmail',  // missing quotes + parameterization
);

// ✅ SECURE — parameterized rawQuery
Future<List<Map<String, dynamic>>> getUserByName(String username) {
  return db.rawQuery('SELECT * FROM users WHERE name = ?', [username]);
}

// ✅ SECURE — using the high-level query helper with whereArgs
Future<List<Map<String, dynamic>>> getUserByEmail(String email) {
  return db.query(
    'users',
    where: 'email = ?',
    whereArgs: [email],  // sqflite escapes and binds this safely
  );
}

// ✅ SECURE — parameterized insert
await db.insert('users', {'name': username, 'email': email});

// ✅ SECURE — encrypted database (sqflite_sqlcipher)
import 'package:sqflite_sqlcipher/sqflite.dart';

final db = await openDatabase(
  path,
  password: encryptionKey,  // retrieve from flutter_secure_storage, never hardcoded
);
```

---

## 5. Command Injection via `dart:io` `Process.run()` / `Process.start()`

**Vulnerability:** `dart:io`'s `Process.run()` and `Process.start()` accept a command and a list of arguments. When `runInShell: true` is passed, the process is spawned via `/bin/sh` (Unix) or `cmd.exe` (Windows), and shell metacharacters in arguments (`&`, `;`, `|`, `$(...)`, backticks) are interpreted as shell operators, enabling command injection. On Windows, batch files (`.bat`, `.cmd`) are always run through a shell regardless of `runInShell`, making Windows-targeting server-side Dart especially dangerous for `.bat` execution.

**References:** CWE-78, CWE-88

### Mandatory Rules

- **Never use `runInShell: true` with any argument derived from user input** — shell metacharacters in arguments will be interpreted as shell operators.
- **Pass arguments as a separate list** — `Process.run('git', ['clone', userUrl])` not `Process.run('sh', ['-c', 'git clone $userUrl'])`.
- **Validate and allowlist command arguments** before passing them to `Process.run()` — reject input containing `/`, `..`, `&`, `;`, `|`, `$`, backticks.
- **On Windows, avoid executing `.bat`/`.cmd` files with user-controlled arguments** — they are always shell-expanded.
- **Prefer library alternatives to shell execution** — use Dart's `dart:io` `Directory`, `File`, `HttpClient` APIs instead of shelling out to `ls`, `curl`, etc.
- **Restrict `dart:io` access** — Flutter mobile apps should not use `Process.run()` at all; it is only available on dart:io platforms (desktop, server).

```dart
// ❌ INSECURE — shell=true with user input; allows command injection
Future<void> cloneRepo(String repoUrl) async {
  await Process.run('sh', ['-c', 'git clone $repoUrl'], runInShell: true);
  // Attacker: 'https://x.com/repo; rm -rf /'
}

// ❌ INSECURE — runInShell with concatenated string
await Process.run('bash', ['-c', 'convert $userFile output.png'], runInShell: true);

// ✅ SECURE — arguments as separate list, no shell interpolation
Future<void> cloneRepo(String repoUrl) async {
  // Validate repoUrl is a valid git URL before this call
  if (!RegExp(r'^https://[a-zA-Z0-9._/-]+\.git$').hasMatch(repoUrl)) {
    throw ArgumentError('Invalid repository URL');
  }
  await Process.run('git', ['clone', '--', repoUrl]);
  // Each list element is passed as a literal argument; no shell expansion
}

// ✅ SECURE — no shell, arguments separated, validated input
await Process.run('ffmpeg', [
  '-i', inputFile,  // validate inputFile is within allowed directory
  '-vf', 'scale=720:-1',
  outputFile,
]);
```

---

## 6. Path Traversal via `dart:io` File Operations

**Vulnerability:** `dart:io`'s `File`, `Directory`, and `RandomAccessFile` classes perform no path sanitization. If user-supplied input is used to construct a file path, an attacker can supply `../` sequences to escape the intended directory — reading `/etc/passwd`, overwriting application files, or accessing other users' data. `CVE-2024-54461` in `file_selector_android` (CVSS 7.1 HIGH, fixed v0.5.1+12, Jan 2025) demonstrated this exact pattern: unsanitized filenames from a malicious document provider allowed an attacker to overwrite internal app cache files.

**References:** CWE-22, CWE-23, CVE-2024-54461 (file_selector_android path traversal, HIGH, fixed 0.5.1+12)

### Mandatory Rules

- **Canonicalize all file paths before use** — use `path.canonicalize()` from `package:path` and verify the resolved path starts with the expected base directory.
- **Never use user-supplied filenames directly** — generate server-side UUIDs for upload storage, or strictly allowlist permitted characters.
- **Reject filenames containing path separators** (`/`, `\`) and dot sequences (`..`).
- **Upgrade `file_selector_android` to ≥0.5.1+12** to fix CVE-2024-54461.
- **Store uploaded files outside the web root** on Dart server applications; serve through a streaming handler.

```dart
// ❌ INSECURE — user-controlled path; traversal to ../../etc/passwd
Future<String> readUserFile(String filename) async {
  final file = File('/app/uploads/$filename');
  return file.readAsString();  // attacker passes: ../../etc/passwd
}

// ❌ INSECURE — no canonicalization before open
Future<void> writeFile(String userPath, List<int> data) async {
  final file = File('/var/app/data/$userPath');
  await file.writeAsBytes(data);
}

// ✅ SECURE — canonicalize and verify prefix
import 'package:path/path.dart' as path;
import 'dart:io';

Future<String> readUserFile(String filename) async {
  const baseDir = '/app/uploads';
  // Reject suspicious characters early
  if (filename.contains('/') || filename.contains('\\') || filename.contains('..')) {
    throw ArgumentError('Invalid filename');
  }
  final resolvedPath = path.canonicalize(path.join(baseDir, filename));
  // Double-check the canonical path stays within baseDir
  if (!resolvedPath.startsWith(path.canonicalize(baseDir) + Platform.pathSeparator)) {
    throw SecurityException('Path traversal attempt detected');
  }
  return File(resolvedPath).readAsString();
}

// ✅ SECURE — server-generated filenames for uploads
import 'package:uuid/uuid.dart';

Future<String> storeUpload(List<int> data, String originalName) async {
  final ext = path.extension(originalName).toLowerCase();
  const allowedExtensions = {'.jpg', '.jpeg', '.png', '.pdf'};
  if (!allowedExtensions.contains(ext)) throw ArgumentError('Unsupported type');
  final safeFilename = '${const Uuid().v4()}$ext';
  final targetPath = path.join('/var/app/uploads', safeFilename);
  await File(targetPath).writeAsBytes(data);
  return safeFilename;
}
```

---

## 7. Insecure Deserialization with `dart:convert` `jsonDecode`

**Vulnerability:** `dart:convert`'s `jsonDecode()` returns `dynamic` — a runtime type with no compile-time safety. Casting the result to a concrete type without validation (e.g., `(json['id'] as int)`) throws a `TypeError` if the server sends an unexpected type, creating denial-of-service. More critically, trusting the content of deserialized JSON without validation enables business logic attacks: a JSON field that should be `int` receiving `null` or `String` can bypass authentication checks, corrupt database writes, or overflow integer arithmetic. `GHSA-3hpf-ff72-j67p` (shared_preferences_android ≤2.3.3, Dec 2024) demonstrated that deserialization of special string prefixes could lead to arbitrary class instantiation.

**References:** CWE-502, CWE-20, GHSA-3hpf-ff72-j67p (shared_preferences_android deserialization, Low, fixed 2.3.4)

### Mandatory Rules

- **Validate the type of every field after `jsonDecode()`** — never assume the server sends the expected type.
- **Use `json_serializable` or `freezed` code generation** — strongly-typed `fromJson` constructors with explicit field handling prevent silent type coercions.
- **Never cast `dynamic` blindly** — always use null-safe patterns: `json['field'] as String? ?? ''` not `json['field'] as String`.
- **Validate semantic constraints after deserialization** — valid ranges for integers, allowed characters for strings, positive-only amounts, etc.
- **Upgrade `shared_preferences_android` to ≥2.3.4** to fix GHSA-3hpf-ff72-j67p.

```dart
// ❌ INSECURE — unchecked casts; TypeError on malformed JSON; logic bypass on null
Map<String, dynamic> json = jsonDecode(response.body);
final userId = json['userId'] as int;        // crashes if string/null
final role = json['role'] as String;         // attacker sends 'admin' instead of 'user'
final amount = json['amount'] as double;     // negative values not checked

// ❌ INSECURE — no validation of semantic constraints
final price = json['price'] as num;  // could be negative, NaN, or Infinity

// ✅ SECURE — defensive deserialization with explicit validation
class UserResponse {
  final int userId;
  final String role;
  final double amount;

  UserResponse({required this.userId, required this.role, required this.amount});

  factory UserResponse.fromJson(Map<String, dynamic> json) {
    final userId = json['userId'];
    if (userId is! int || userId <= 0) throw FormatException('Invalid userId');

    final role = json['role'];
    const allowedRoles = {'user', 'moderator'};  // never 'admin' from client
    if (role is! String || !allowedRoles.contains(role)) {
      throw FormatException('Invalid role');
    }

    final amount = json['amount'];
    if (amount is! num || amount < 0 || amount.isNaN || amount.isInfinite) {
      throw FormatException('Invalid amount');
    }

    return UserResponse(userId: userId, role: role, amount: amount.toDouble());
  }
}

// ✅ SECURE — use json_serializable (add to pubspec: json_annotation + build_runner)
@JsonSerializable()
class UserResponse {
  final int userId;
  @JsonKey(unknownEnumValue: UserRole.user)
  final UserRole role;
  final double amount;

  UserResponse({required this.userId, required this.role, required this.amount});
  factory UserResponse.fromJson(Map<String, dynamic> json) => _$UserResponseFromJson(json);
}
```

---

## 8. WebView Security — `webview_flutter` JavaScript Injection and Navigation

**Vulnerability:** Flutter's `webview_flutter` renders untrusted web content inside the app's process. When JavaScript is enabled and the WebView loads attacker-controlled URLs, JavaScript can access `JavascriptChannel` methods that bridge to native Dart code, enabling XSS-to-native escalation. Not implementing a `navigationDelegate` allows the WebView to navigate to arbitrary URLs including `file://` URIs (local file read) or `javascript:` URIs. Additionally, `webview_flutter` 0.3.23 was affected by CVE-2020-6506, a Universal XSS via `FileProvider` on Android.

**References:** CWE-79, CWE-601, CVE-2020-6506 (webview_flutter UXSS, Android)

### Mandatory Rules

- **Disable JavaScript in WebView unless it is explicitly required** — `javascriptMode: JavascriptMode.disabled` (v3) or `WebViewWidget` with no `JavascriptChannels`.
- **When JavaScript is enabled, implement a strict `navigationDelegate`** — allowlist only expected origins; block `javascript:`, `file://`, and unexpected schemes.
- **Never load untrusted user-supplied URLs directly into a WebView** — validate the URL is `https://` and matches an allowed domain allowlist before loading.
- **Avoid exposing sensitive `JavascriptChannel` methods** — treat every JavaScript bridge as a public API callable by any page loaded in the WebView.
- **Set `allowsInlineMediaPlayback: false` and restrict permissions** — follow the principle of least privilege for WebView capabilities.
- **Upgrade `webview_flutter` to a current version** — the 0.3.23 UXSS (CVE-2020-6506) is present in all older versions.

```dart
// ❌ INSECURE — JavaScript enabled, no navigation restriction, arbitrary URL loaded
WebView(
  initialUrl: userProvidedUrl,                    // attacker controls this
  javascriptMode: JavascriptMode.unrestricted,    // JS can call native bridges
  javascriptChannels: {
    JavascriptChannel(
      name: 'NativeBridge',
      onMessageReceived: (msg) => executeNativeAction(msg.message),  // XSS → native
    ),
  },
)

// ✅ SECURE — allowlisted navigation, restricted JavaScript
WebView(
  initialUrl: sanitizeUrl(userProvidedUrl),
  javascriptMode: JavascriptMode.disabled,  // disable unless required
  navigationDelegate: (NavigationRequest request) {
    final uri = Uri.tryParse(request.url);
    if (uri == null || uri.scheme != 'https') {
      return NavigationDecision.prevent;
    }
    const allowedHosts = {'example.com', 'api.example.com'};
    if (!allowedHosts.contains(uri.host)) {
      return NavigationDecision.prevent;
    }
    return NavigationDecision.navigate;
  },
)

// ✅ SECURE — URL validation helper
String? sanitizeWebViewUrl(String url) {
  final uri = Uri.tryParse(url);
  if (uri == null || uri.scheme != 'https') return null;
  const allowedHosts = {'example.com', 'docs.example.com'};
  if (!allowedHosts.contains(uri.host)) return null;
  return uri.toString();
}
```

---

## 9. Deep Link / URL Scheme Hijacking

**Vulnerability:** Custom URL schemes (`myapp://`) can be registered by any app on the device. A malicious app on the same device can register `myapp://` and intercept deep links intended for your application, including OAuth authorization codes, password reset tokens, and other sensitive parameters passed through the URI. This is a well-documented attack: in a 2017 study of 160,000+ Android apps, `google.com` was registered by 480 non-Google apps and `google.navigation` (Google Maps' scheme) was hijacked by 79 different developers.

**References:** CWE-939, OWASP MASVS-PLATFORM-3, MASTG-TEST-0028, iOS URL Scheme Hijacking

### Mandatory Rules

- **Use HTTPS Universal Links (iOS) and Android App Links instead of custom URL schemes** — they verify domain ownership via `apple-app-site-association` / `assetlinks.json` files hosted on your server.
- **Validate all data received via deep links** — treat deep link parameters as untrusted user input: validate types, lengths, and allowed values.
- **Never pass sensitive tokens through URL schemes** — use App Links/Universal Links for OAuth redirect URIs, not custom schemes.
- **For OAuth, use `package:flutter_appauth`** — it implements the PKCE flow using the system browser with verified redirect URIs.
- **Verify the deep link's host and path match expected patterns** before extracting parameters.

```dart
// ❌ INSECURE — custom scheme; any app on device can intercept
// AndroidManifest.xml:
// <intent-filter>
//   <data android:scheme="myapp" android:host="oauth"/>
// </intent-filter>
//
// OAuth redirect: myapp://oauth?code=SECRET_AUTH_CODE  ← interceptable

// ❌ INSECURE — unvalidated deep link parameters
void handleDeepLink(Uri link) {
  final userId = link.queryParameters['userId'];
  navigateTo('/user/$userId');  // path traversal or IDOR via crafted link
}

// ✅ SECURE — Android App Links (AndroidManifest.xml)
// <intent-filter android:autoVerify="true">
//   <action android:name="android.intent.action.VIEW"/>
//   <category android:name="android.intent.category.DEFAULT"/>
//   <category android:name="android.intent.category.BROWSABLE"/>
//   <data android:scheme="https" android:host="example.com" android:pathPrefix="/app"/>
// </intent-filter>
// Requires: https://example.com/.well-known/assetlinks.json

// ✅ SECURE — validated deep link handling
void handleDeepLink(Uri link) {
  if (link.scheme != 'https' || link.host != 'example.com') return;

  final userId = link.queryParameters['userId'];
  if (userId == null || !RegExp(r'^\d+$').hasMatch(userId)) return;

  final numericId = int.parse(userId);
  if (numericId <= 0 || numericId > 2147483647) return;

  // Still verify ownership server-side; this is client-side pre-check only
  navigateTo('/user/$numericId');
}

// ✅ SECURE — OAuth via flutter_appauth (PKCE + system browser + App Links redirect)
import 'package:flutter_appauth/flutter_appauth.dart';

final appAuth = FlutterAppAuth();
final result = await appAuth.authorizeAndExchangeCode(
  AuthorizationTokenRequest(
    'client_id',
    'https://example.com/callback',  // App Link, not custom scheme
    serviceConfiguration: AuthorizationServiceConfiguration(
      authorizationEndpoint: 'https://idp.example.com/auth',
      tokenEndpoint: 'https://idp.example.com/token',
    ),
    scopes: ['openid', 'profile'],
  ),
);
```

---

## 10. Screenshot and Screen Recording Protection

**Vulnerability:** On Android, apps do not prevent screenshots or screen recording by default. The Android task switcher also captures a thumbnail of the last app screen. If your app displays sensitive information (banking data, health records, messages, authentication codes), this thumbnail and any screenshots are stored in plaintext on the device and accessible to other apps with `READ_EXTERNAL_STORAGE` permission, screen recording software, or physical device access. On iOS, the operating system notifies apps of screenshots but does not block them by default.

**References:** OWASP MASVS-RESILIENCE-4, CWE-200

### Mandatory Rules

- **Set `FLAG_SECURE` on the Android window** for any screen displaying sensitive information — this prevents screenshots, screen recording, and appears black in the task switcher.
- **On iOS, overlay a privacy screen on `applicationWillResignActive`** to prevent the task switcher thumbnail from capturing sensitive content.
- **Use `package:screen_secure` or `package:no_screenshot`** to implement cross-platform screenshot prevention with a single API.
- **Apply screenshot protection selectively** — screens with PII, financial data, credentials, or auth codes; not every screen in the app.

```kotlin
// ✅ SECURE — Android (MainActivity.kt) — set FLAG_SECURE
import android.view.WindowManager
import io.flutter.embedding.android.FlutterActivity

class MainActivity : FlutterActivity() {
  override fun onResume() {
    super.onResume()
    window.addFlags(WindowManager.LayoutParams.FLAG_SECURE)
  }
  // To allow screenshots on non-sensitive screens:
  // window.clearFlags(WindowManager.LayoutParams.FLAG_SECURE)
}
```

```swift
// ✅ SECURE — iOS (AppDelegate.swift) — blur on background
import UIKit
import Flutter

@UIApplicationMain
class AppDelegate: FlutterAppDelegate {
  var privacyView: UIView?

  override func applicationWillResignActive(_ application: UIApplication) {
    let blur = UIBlurEffect(style: .dark)
    let blurView = UIVisualEffectView(effect: blur)
    blurView.frame = window!.bounds
    window?.addSubview(blurView)
    privacyView = blurView
  }

  override func applicationDidBecomeActive(_ application: UIApplication) {
    privacyView?.removeFromSuperview()
    privacyView = nil
  }
}
```

```dart
// ✅ SECURE — cross-platform with package:no_screenshot
import 'package:no_screenshot/no_screenshot.dart';

class SecureScreen extends StatefulWidget { ... }

class _SecureScreenState extends State<SecureScreen> {
  final _noScreenshot = NoScreenshot.instance;

  @override
  void initState() {
    super.initState();
    _noScreenshot.screenshotOff();  // disable on enter
  }

  @override
  void dispose() {
    _noScreenshot.screenshotOn();   // re-enable on exit
    super.dispose();
  }
}
```

---

## 11. Biometric Authentication Bypass

**Vulnerability:** The `local_auth` package's `authenticate()` method returns a `bool`. On Android, calling `authenticate()` without a `CryptoObject` only performs a "weak" biometric check — the result can be bypassed by hooking the `authenticate()` return value using Frida or other instrumentation frameworks, changing `false` to `true`. Without a hardware-backed `CryptoObject`, biometric authentication provides no cryptographic proof that the authorized user performed the action.

**References:** CWE-308, CWE-287, OWASP MASVS-AUTH-2

### Mandatory Rules

- **Never gate sensitive operations on a boolean `authenticate()` result alone** — the boolean can be hooked by an attacker with Frida.
- **Tie biometric authentication to a cryptographic operation** — use `BiometricPrompt` with a `CryptoObject` on Android (via platform channel or a package like `package:biometric_storage`).
- **Store the actual secret in the device keystore and unlock it with biometrics** — `package:biometric_storage` provides this pattern: the key is hardware-backed and only released after a successful biometric check.
- **Implement fallback to device PIN/password** — biometrics are not available on all devices or after 5 failed attempts.
- **Do not store biometric templates or intermediate data** — the platform APIs handle biometric processing securely; do not implement custom biometric logic.

```dart
// ❌ INSECURE — boolean result is hookable; no cryptographic binding
import 'package:local_auth/local_auth.dart';

Future<void> performSensitiveOperation() async {
  final auth = LocalAuthentication();
  final authenticated = await auth.authenticate(
    localizedReason: 'Please authenticate',
  );
  if (authenticated) {
    // Attacker hooks authenticate() to return true → bypasses this check
    await transferFunds();
  }
}

// ✅ SECURE — biometric unlocks a hardware-backed key; cannot be bypassed by hooking bool
import 'package:biometric_storage/biometric_storage.dart';

Future<void> performSensitiveOperation() async {
  // Data is stored encrypted in the Keystore/Keychain; biometric success is
  // required at the hardware level to decrypt — not just a boolean check
  final store = await BiometricStorage().getStorage(
    'sensitive_key',
    options: StorageFileInitOptions(
      authenticationRequired: true,
      authenticationValidityDurationSeconds: 30,
    ),
  );
  final secret = await store.read();  // throws if biometric fails
  if (secret == null) throw StateError('No key available');
  await transferFunds(secret);
}
```

---

## 12. Hardcoded Secrets and `--dart-define` False Security

**Vulnerability:** Dart code is compiled to native AOT machine code for release builds, but string literals (including those injected via `--dart-define`) are embedded in the binary in plaintext or easily decodable form. On iOS, `--dart-define` values are stored as Base64 in `Info.plist` — decoding is trivial. On Android, strings are extractable from the AOT `libapp.so` using tools like `strings`, `blutter`, or `jadx`. Treating compiled Dart code as opaque is a critical misconception — API keys, endpoints, and configuration values hardcoded this way are routinely extracted in mobile penetration tests.

**References:** CWE-798, CWE-321, OWASP Mobile Top 10:2024 M9

### Mandatory Rules

- **Never hardcode API keys, passwords, encryption keys, or client secrets** in Dart source code or via `--dart-define`.
- **Use a backend proxy for sensitive API calls** — the mobile app authenticates to your backend, and the backend uses the secret API key. The mobile app never holds the raw key.
- **Retrieve secrets at runtime from your authenticated backend**, not from the app binary.
- **If some configuration must be in the binary, treat it as public** — use API key restrictions (IP allowlist, referer, capability scoping) to limit blast radius.
- **Use `--obfuscate --split-debug-info=<dir>` when building** — this renames Dart symbols, raising the reverse-engineering bar, but does not encrypt strings.
- **Run Gitleaks or TruffleHog** in pre-commit hooks and CI to detect secrets committed to source control.

```dart
// ❌ INSECURE — hardcoded secret in source
const apiKey = 'sk-live-abc123xyz789';
const dbPassword = 'P@ssw0rd!';

// ❌ INSECURE — dart-define: extractable from Info.plist (iOS) or strings in .so (Android)
// flutter run --dart-define=API_KEY=sk-live-abc123xyz789
const apiKey = String.fromEnvironment('API_KEY');  // still in binary as plaintext

// ✅ SECURE — secrets fetched at runtime from authenticated backend
class SecureApiClient {
  String? _cachedToken;

  Future<String> _getToken() async {
    if (_cachedToken != null) return _cachedToken!;
    // App authenticates to your backend using user credentials
    // Backend issues a short-lived, scoped token — not the raw API key
    final response = await http.post(
      Uri.parse('https://api.example.com/auth/token'),
      headers: {'Authorization': 'Bearer ${await _getUserJwt()}'},
    );
    _cachedToken = jsonDecode(response.body)['token'] as String;
    return _cachedToken!;
  }

  Future<http.Response> callThirdPartyApi(String endpoint) async {
    final token = await _getToken();
    return http.get(Uri.parse(endpoint), headers: {'Authorization': 'Bearer $token'});
  }
}
```

---

## 13. Sensitive Data in Logs — `print()` and `debugPrint()` in Production

**Vulnerability:** `print()` in Flutter routes to `stdout`, which is captured in `adb logcat` on Android and the system log on iOS — readable by any app with `READ_LOGS` permission (Android) or via connected developer tools. `debugPrint()` also reaches logcat in release builds. Flutter's `release` mode does NOT strip `print()` statements — they continue to execute and emit to the system log. Logging tokens, passwords, PII, or error stack traces creates a persistent record accessible to device forensics, crash reporting services, and log aggregators.

**References:** CWE-532, CWE-200, OWASP Mobile Top 10:2024 M4

### Mandatory Rules

- **Never call `print()` or `debugPrint()` with sensitive data** — tokens, passwords, PII, payment card data, health data, cryptographic material.
- **Gate all debug logging behind `kDebugMode`** — `if (kDebugMode) print(...)` is tree-shaken in release builds.
- **Use `dart:developer`'s `log()` function** for structured logging — it is automatically no-op'd in release mode.
- **Implement a logging service** that filters `Level.FINE`/`Level.FINEST` in production and never logs sensitive field values.
- **Sanitize log output** — log error types and codes, not exception messages that may contain user data.
- **Configure crash reporting (Crashlytics, Sentry)** to redact PII before uploading crash reports.

```dart
// ❌ INSECURE — print() in release mode → logcat → readable by attacker
void processPayment(String cardNumber, String cvv) {
  print('Processing payment for card: $cardNumber, CVV: $cvv');
  // ...
}

// ❌ INSECURE — logging auth token (common in error handlers)
try {
  final token = await auth.login(username, password);
  print('Login successful: token=$token');
} catch (e) {
  print('Auth error: $e');  // e.toString() may contain credentials
}

// ✅ SECURE — kDebugMode gate (tree-shaken from release builds)
import 'package:flutter/foundation.dart';

void processPayment(String cardNumber, String cvv) {
  if (kDebugMode) {
    print('Processing payment for card ending: ${cardNumber.substring(cardNumber.length - 4)}');
  }
  // ...
}

// ✅ SECURE — dart:developer log (no-op in release)
import 'dart:developer' as dev;

void onLoginSuccess(String userId) {
  dev.log('Login successful for user: $userId', name: 'auth');
  // Never log the token itself
}

// ✅ SECURE — structured logging with level control
import 'package:logging/logging.dart';

final _log = Logger('auth');

void configureLogging() {
  if (kReleaseMode) {
    Logger.root.level = Level.WARNING;  // only warnings and errors in production
  } else {
    Logger.root.level = Level.ALL;
  }
  Logger.root.onRecord.listen((record) {
    // In production, send only to crash reporting — with PII redacted
    if (kReleaseMode && record.level >= Level.SEVERE) {
      CrashReporter.report(record.message);  // do not include record.error if it has PII
    }
  });
}
```

---

## 14. Dart FFI (`dart:ffi`) Memory Safety

**Vulnerability:** `dart:ffi` allows Dart code to call native C libraries, bypassing Dart's memory safety guarantees. All pointer arithmetic, buffer sizing, and memory lifetimes must be managed manually. Errors include: passing a Dart-allocated pointer to C code that calls `free()` (double-free / heap corruption on Windows, which uses different allocators); forgetting to call `malloc.free()` on `Pointer` objects (memory leak leading to OOM); casting `Pointer<Void>` to an incorrect type (type confusion, potential arbitrary code execution); and writing beyond an allocated buffer (buffer overflow — impossible in pure Dart, but trivially possible via FFI).

**References:** CWE-119, CWE-416, CWE-476, Flutter Security False Positives documentation

### Mandatory Rules

- **Pair every `malloc()` / `calloc()` with `malloc.free()`** — use `try`/`finally` or `Arena` (from `package:ffi`) to guarantee deallocation even on exceptions.
- **Never pass a Dart FFI-allocated pointer to C code that calls `free()`** — on Windows especially, the allocators are different (`HeapAlloc` vs `malloc`). Use `malloc` from `package:ffi` on both sides.
- **Always verify struct sizes and alignment** before using `Pointer<T>.cast<U>()`.
- **Use `Arena` from `package:ffi` for scoped allocations** — memory is freed when the `Arena` goes out of scope, preventing leaks.
- **Validate all sizes before `allocate()` calls** — check for zero-size and integer overflow in size calculations.
- **Prefer Dart-native implementations** over FFI where performance is not critical — pure Dart code is memory-safe and cannot produce buffer overflows.

```dart
// ❌ INSECURE — memory leak: no free() if exception occurs
import 'dart:ffi';
import 'package:ffi/ffi.dart';

void processData(List<int> data) {
  final ptr = malloc.allocate<Uint8>(data.length);
  for (var i = 0; i < data.length; i++) {
    ptr[i] = data[i];
  }
  nativeLib.processBuffer(ptr, data.length);
  malloc.free(ptr);  // ← not called if nativeLib throws
}

// ❌ INSECURE — buffer overflow: size not checked before write
void fillBuffer(Pointer<Uint8> buf, int bufSize, List<int> data) {
  for (var i = 0; i < data.length; i++) {  // data.length may exceed bufSize
    buf[i] = data[i];
  }
}

// ✅ SECURE — Arena ensures free() even on exception
import 'package:ffi/ffi.dart';

void processData(List<int> data) {
  using((Arena arena) {
    final ptr = arena.allocate<Uint8>(data.length);
    for (var i = 0; i < data.length; i++) {
      ptr[i] = data[i];
    }
    nativeLib.processBuffer(ptr, data.length);
    // arena.releaseAll() called automatically on scope exit
  });
}

// ✅ SECURE — bounds check before write
void fillBuffer(Pointer<Uint8> buf, int bufSize, List<int> data) {
  if (data.length > bufSize) throw ArgumentError('data exceeds buffer size');
  for (var i = 0; i < data.length; i++) {
    buf[i] = data[i];
  }
}
```

---

## 15. Cryptography Misuse — `package:encrypt` and `package:pointycastle`

**Vulnerability:** Common cryptographic misuse patterns in Flutter/Dart:
- AES-ECB mode: encrypts each block independently — identical plaintext blocks produce identical ciphertext blocks, leaking data patterns (the "ECB penguin" attack).
- IV reuse: reusing an IV with the same key in AES-CBC or AES-CTR/GCM destroys confidentiality or, in GCM, allows forging of authenticated ciphertext.
- `package:crypto` (MD5, SHA-1) used for password hashing: both are fast hashing algorithms not suitable for passwords — bcrypt/Argon2 are required.
- Hardcoded AES keys: keys stored in source code are extractable from the binary.

**References:** CWE-327, CWE-329, CWE-916, NIST SP 800-38A

### Mandatory Rules

- **Never use AES-ECB mode** — use AES-GCM (preferred, provides authentication) or AES-CBC with a random IV.
- **Generate a unique, random IV/nonce for every encryption operation** — never reuse an IV with the same key.
- **For AES-GCM, use a 96-bit (12-byte) nonce** — longer nonces reduce the collision probability of random nonces.
- **Never use `package:crypto`'s MD5 or SHA-1 for password hashing** — use `package:bcrypt` or `package:argon2_flutter` (Argon2id).
- **Use `dart:math`'s `Random.secure()` or `package:cryptography`'s key generation APIs** — never `Random()` for key/IV generation.
- **Store encryption keys in `flutter_secure_storage`** — never hardcode keys or derive them from constant strings without a KDF (PBKDF2/Argon2).

```dart
// ❌ INSECURE — AES-ECB mode; identical blocks produce identical ciphertext
import 'package:encrypt/encrypt.dart';

String encryptECB(String plaintext, Key key) {
  final encrypter = Encrypter(AES(key, mode: AESMode.ecb));  // ECB: never use
  return encrypter.encrypt(plaintext).base64;
}

// ❌ INSECURE — reusing a hardcoded IV
final iv = IV.fromUtf8('1234567890123456');  // static IV — catastrophic reuse

// ❌ INSECURE — MD5 for password hashing
import 'package:crypto/crypto.dart';

String hashPassword(String password) {
  return md5.convert(utf8.encode(password)).toString();  // MD5: broken, fast, no salt
}

// ✅ SECURE — AES-256-GCM with random nonce; authenticated encryption
import 'package:cryptography/cryptography.dart';

Future<List<int>> encryptAesGcm(List<int> plaintext, SecretKey key) async {
  final algorithm = AesGcm.with256bits();
  final secretBox = await algorithm.encrypt(
    plaintext,
    secretKey: key,
    // nonce is auto-generated per call using Random.secure() internally
  );
  // secretBox contains: nonce + ciphertext + MAC — all needed for decryption
  return [
    ...secretBox.nonce,
    ...secretBox.cipherText,
    ...secretBox.mac.bytes,
  ];
}

// ✅ SECURE — key derived from password with Argon2
import 'package:argon2_flutter/argon2_flutter.dart';

Future<SecretKey> deriveKey(String password, List<int> salt) async {
  final result = await Argon2Flutter.hash(
    password: password,
    salt: salt,
    type: Argon2Type.id,
    version: Argon2Version.V13,
    memory: 65536,      // 64 MiB
    iterations: 3,
    parallelism: 4,
    hashLength: 32,
  );
  return SecretKey(result.bytes);
}

// ✅ SECURE — password hashing with bcrypt
import 'package:bcrypt/bcrypt.dart';

String hashPassword(String password) {
  return BCrypt.hashpw(password, BCrypt.gensalt(logRounds: 12));
}

bool verifyPassword(String password, String hash) {
  return BCrypt.checkpw(password, hash);
}
```

---

## 16. Platform Channel (`MethodChannel`) Security

**Vulnerability:** Flutter's `MethodChannel` provides bidirectional communication between Dart and native Android/iOS code. On the Dart side, data from a `MethodChannel` invocation arrives as `dynamic`. On the native side, arguments from Dart arrive as platform objects. If either side trusts the other without validation, an attacker who can invoke the channel (via a compromised JavaScript context in a WebView, a compromised plugin, or a reverse-engineered app) can pass unexpected types or malicious values. Plugin-to-plugin IPC via `BasicMessageChannel` with well-known channel names is also exposed.

**References:** CWE-20, OWASP MASVS-PLATFORM-1

### Mandatory Rules

- **Validate all data received via `MethodChannel` on both the Dart and native sides** — type-check, range-check, and validate every argument.
- **Do not expose MethodChannels to WebView JavaScript** — `JavascriptChannel` should never directly forward user input to a MethodChannel without sanitization.
- **Use unique, non-guessable channel names** for internal plugin channels — `com.example.myapp.internal.payment` not `payment`.
- **Validate method names against an allowlist** on the native side — reject unknown method names with a meaningful error rather than silently ignoring them.
- **Never pass secrets or tokens through MethodChannel** — use native platform Keystore APIs directly.

```dart
// ❌ INSECURE — unchecked dynamic cast on MethodChannel result
final channel = MethodChannel('com.example.crypto');

Future<void> processResult() async {
  final result = await channel.invokeMethod('getKey');
  final key = result as String;  // crashes if native returns null or wrong type
  useKey(key);
}

// ❌ INSECURE — forwarding WebView user input directly to native
JavascriptChannel(
  name: 'NativeChannel',
  onMessageReceived: (JavascriptMessage msg) {
    // No validation: msg.message from untrusted web content goes straight to native
    channel.invokeMethod('execute', {'command': msg.message});
  },
)

// ✅ SECURE — validated MethodChannel usage
final channel = MethodChannel('com.example.myapp.v1.secure');

Future<String> getKey() async {
  final dynamic result = await channel.invokeMethod<dynamic>('getKey');
  if (result is! String || result.isEmpty || result.length > 256) {
    throw StateError('Unexpected key format from native');
  }
  return result;
}

// ✅ SECURE — sanitize before forwarding to native
JavascriptChannel(
  name: 'SafeChannel',
  onMessageReceived: (JavascriptMessage msg) {
    final input = msg.message.trim();
    // Strict allowlist: only alphanumeric + hyphen, max 64 chars
    if (!RegExp(r'^[a-zA-Z0-9\-]{1,64}$').hasMatch(input)) return;
    channel.invokeMethod('lookupItem', {'id': input});
  },
)
```

---

## 17. JWT Validation

**Vulnerability:** Common JWT implementation errors in Dart/Flutter: (1) using `JWT.decode()` instead of `JWT.verify()` — decoding skips signature verification, accepting any payload including attacker-forged tokens; (2) accepting the `none` algorithm — some libraries accept `{"alg":"none"}` in the header if algorithm validation is not enforced; (3) not validating `iss`, `aud`, `exp`, and `nbf` claims — allowing expired, wrong-audience, or wrong-issuer tokens; (4) trusting the `alg` header from the token itself when verifying (algorithm confusion attacks).

**References:** CWE-347, CWE-290

### Mandatory Rules

- **Always use `JWT.verify()` with an explicit algorithm** — never `JWT.decode()` for tokens used for authorization.
- **Specify the expected algorithm explicitly** — do not allow the token header to dictate the algorithm; use `JWTAlgorithm.HS256` / `JWTAlgorithm.RS256` etc. explicitly.
- **Validate `exp`, `iss`, and `aud` claims** after successful signature verification.
- **On mobile, do not perform JWT verification client-side for authorization decisions** — verify on the server; the mobile app only passes the token to the backend.
- **Store JWTs in `flutter_secure_storage`** — never `SharedPreferences`, never `dart:html` `window.localStorage` on web.

```dart
// ❌ INSECURE — decode() skips signature verification
import 'package:dart_jsonwebtoken/dart_jsonwebtoken.dart';

void processToken(String token) {
  final jwt = JWT.decode(token);  // no signature check — attacker can forge any payload
  final userId = jwt.payload['sub'];
  grantAccess(userId);
}

// ❌ INSECURE — algorithm not specified; may accept alg:none
JWT.verify(token, SecretKey('secret'));  // missing JWTAlgorithm.HS256

// ✅ SECURE — verify with explicit algorithm and claim validation
import 'package:dart_jsonwebtoken/dart_jsonwebtoken.dart';

void processToken(String token) {
  try {
    final jwt = JWT.verify(
      token,
      SecretKey(serverSecret),  // or RSAPublicKey for RS256
      // dart_jsonwebtoken v2+ enforces algorithm in the key type
    );

    final payload = jwt.payload as Map<String, dynamic>;

    // Validate standard claims
    final exp = payload['exp'];
    if (exp is! int || DateTime.fromMillisecondsSinceEpoch(exp * 1000).isBefore(DateTime.now())) {
      throw JWTExpiredException();
    }

    final iss = payload['iss'];
    if (iss != 'https://idp.example.com') throw JWTInvalidException('Bad issuer');

    final aud = payload['aud'];
    if (aud != 'api.example.com') throw JWTInvalidException('Bad audience');

    grantAccess(payload['sub'] as String);
  } on JWTException catch (e) {
    // Token is invalid — deny access, log the failure (not the token)
    denyAccess();
  }
}
```

---

## 18. Cleartext HTTP Traffic and Network Security

**Vulnerability:** Flutter apps targeting Android API 28+ block cleartext HTTP by default, but this protection is bypassed when developers explicitly allow cleartext traffic in `android:usesCleartextTraffic="true"` in the manifest or via an overly permissive `network_security_config.xml`. On iOS, ATS (App Transport Security) similarly blocks cleartext connections but can be disabled via `NSAllowsArbitraryLoads` in `Info.plist`. Cleartext HTTP exposes all request and response data to network-level MitM attacks.

**References:** CWE-319, OWASP Mobile Top 10:2024 M5, CVE-2022-0451 (Dart HttpClient cross-origin credential leak, fixed Dart 2.16.0)

### Mandatory Rules

- **Never set `android:usesCleartextTraffic="true"` in production manifests** — this flag disables Android's cleartext traffic protection for the entire application.
- **Never set `NSAllowsArbitraryLoads: true` in production `Info.plist`** — use `NSExceptionDomains` for specific necessary exceptions (e.g., local development).
- **All API endpoints must use `https://`** — reject `http://` URIs in API client configuration.
- **Upgrade Dart SDK to ≥2.16.0** to fix CVE-2022-0451 (authorization headers leaked on cross-origin redirects).
- **Set `followRedirects = false` on `HttpClient` for requests with `Authorization` headers** if using Dart <2.16.0, and handle redirects manually.
- **Validate that user-supplied URLs are HTTPS** before making HTTP requests.

```dart
// ❌ INSECURE — accepting http:// URLs
Future<void> fetchData(String baseUrl) async {
  final response = await http.get(Uri.parse('$baseUrl/api/data'));
  // baseUrl could be http://attacker.com
}

// ❌ INSECURE — SSRF: user controls the URL passed to HttpClient
Future<http.Response> proxyRequest(String userUrl) async {
  return http.get(Uri.parse(userUrl));  // user can pass internal service URLs
}

// ✅ SECURE — enforce HTTPS and allowlist hosts
const _allowedApiHosts = {'api.example.com', 'cdn.example.com'};

Future<http.Response> fetchData(String path) async {
  final uri = Uri.https('api.example.com', path);  // hardcoded host; https scheme enforced
  return http.get(uri, headers: {'Authorization': 'Bearer ${await getToken()}'});
}

// ✅ SECURE — SSRF prevention via allowlist
Future<http.Response> fetchExternal(String userUrl) async {
  final uri = Uri.tryParse(userUrl);
  if (uri == null || uri.scheme != 'https' || !_allowedApiHosts.contains(uri.host)) {
    throw ArgumentError('URL not allowed: $userUrl');
  }
  return http.get(uri);
}
```

---

## 19. Supply Chain Security — pub.dev Dependency Management

**Vulnerability:** The Dart/Flutter ecosystem uses pub.dev for package distribution. Risks include: (1) transitive dependencies with unpatched CVEs — `dart pub get` now surfaces advisories from the GitHub Advisory Database, but only for packages in your dependency tree; (2) typosquatting — packages named similarly to popular ones (e.g., `flutter_secure_storagee`); (3) dependency confusion — if an organization uses private packages and an attacker uploads a same-named package to pub.dev with a higher version number, `dart pub get` may resolve to the malicious public package; (4) unpinned version ranges — `^1.0.0` allows automatic upgrade to any 1.x.y version, including future compromised releases.

**References:** CWE-829, OWASP Mobile Top 10:2024 M2, CVE-2021-22568 (Dart SDK credential leak to third-party pub hosts, fixed Dart 2.15.0)

### Mandatory Rules

- **Run `dart pub audit` / `osv-scanner` in CI** — block builds when CRITICAL or HIGH vulnerabilities are reported in direct dependencies.
- **Use exact version pins or tight constraints for security-critical packages** — `flutter_secure_storage: 9.2.2` instead of `^9.0.0`.
- **Commit `pubspec.lock`** to version control for application projects — ensures reproducible builds with known dependency graphs.
- **Review new dependencies before adding** — check pub.dev for maintenance activity, GitHub stars, verified publisher status, and last publish date.
- **Enable GitHub Dependabot for Dart** — GitHub's supply chain security features support pub.dev dependency graphs as of 2022.
- **Upgrade Dart SDK to ≥2.15.0** to fix CVE-2021-22568 (OAuth tokens leaked when publishing to third-party pub hosts).
- **Use `dependency_overrides` only in emergencies** — overrides can hide real version conflicts and must be documented.

```yaml
# ❌ INSECURE — unpinned security-critical dependencies
dependencies:
  flutter_secure_storage: any           # accepts any version including 0.0.1 with bugs
  dio: ">=4.0.0"                        # includes CVE-2021-31402 (CRLF injection)
  http: ^0.12.0                         # very old; missing security fixes

# ✅ SECURE — pinned versions with known-good releases
dependencies:
  flutter_secure_storage: "9.2.2"       # exact version for security packages
  dio: "^5.7.0"                         # ≥5.0.0 required (fixes CVE-2021-31402)
  http: "^1.2.0"                        # current stable release
  dart_jsonwebtoken: "^2.8.0"

# ✅ SECURE — CI audit step (add to CI workflow)
# dart pub get
# dart pub audit               # surfaces pub.dev advisories
# osv-scanner --lockfile pubspec.lock   # cross-references GitHub Advisory Database
```

```bash
# ✅ SECURE — audit commands
dart pub audit                          # built-in: checks GitHub Advisory DB
osv-scanner --lockfile pubspec.lock     # open-source vulnerability scanner
flutter pub outdated                    # shows available updates with changelogs

# ✅ SECURE — build with obfuscation (raises reverse-engineering bar)
flutter build apk --obfuscate --split-debug-info=build/symbols/
flutter build ios --obfuscate --split-debug-info=build/symbols/
```

---

## 20. Code Obfuscation and Runtime Integrity

**Vulnerability:** Flutter AOT snapshots (`libapp.so`) contain function names, class names, string constants, and full method signatures unless `--obfuscate` is passed. Without obfuscation, a decompiler or `strings` command can extract hardcoded values, reveal application logic, and identify security checks (like root detection or license validation) that an attacker can patch out. Note: obfuscation renames symbols but does NOT encrypt string literals or prevent native disassembly.

**References:** OWASP MASVS-RESILIENCE-1, OWASP MASVS-RESILIENCE-3

### Mandatory Rules

- **Always build release binaries with `--obfuscate --split-debug-info=<path>`** — saves the symbol map separately, so crash reports remain readable while the binary is hardened.
- **Store the debug symbols artifact securely** alongside your release build — required to symbolicate crashes from production.
- **Implement root/jailbreak detection** for high-value apps (financial, healthcare) using `package:freerasp` or equivalent — but accept that this can be bypassed and use it as one layer in defense-in-depth.
- **Do not rely on obfuscation to protect secrets** — strings remain readable; secrets must not be in the binary at all.
- **Implement certificate transparency checking** and app signing verification for critical production apps.

```bash
# ❌ INSECURE — release build without obfuscation
flutter build apk --release
# Result: libapp.so contains: class names, method names, string constants including API keys

# ✅ SECURE — obfuscated release build
flutter build apk \
  --obfuscate \
  --split-debug-info=./build/debug-info/  # store securely; needed for crash symbolication

flutter build ios \
  --obfuscate \
  --split-debug-info=./build/debug-info/
```

```dart
// ✅ SECURE — root/jailbreak detection as a defense layer
import 'package:freerasp/freerasp.dart';

Future<void> initSecurity() async {
  final config = TalsecConfig(
    androidConfig: AndroidConfig(
      packageName: 'com.example.myapp',
      certificateHashes: ['your-signing-cert-hash'],
    ),
    iosConfig: IOSConfig(
      bundleIds: ['com.example.myapp'],
      teamId: 'YOUR_TEAM_ID',
    ),
    watcherMail: 'security@example.com',
    isProd: kReleaseMode,
  );

  final callbacks = ThreatCallback(
    onRootDetected: () => _handleThreat('root'),
    onDebuggerDetected: () => _handleThreat('debugger'),
    onTamperDetected: () => _handleThreat('tamper'),
    onHookDetected: () => _handleThreat('hook'),
    onUntrustedInstallationSourceDetected: () => _handleThreat('sideload'),
  );

  await Talsec.instance.start(config, callbacks);
}

void _handleThreat(String type) {
  // Do not exit silently — log the threat and optionally degrade functionality
  logSecurityEvent('threat_detected', {'type': type});
  // Consider: restrict sensitive features, require re-authentication, or notify server
}
```

---

## CVE Reference Table

| CVE / Advisory | Severity | Component | Description | Fixed In |
|---|---|---|---|---|
| CVE-2022-3095 | Critical (9.8) | Dart SDK `dart:uri` | Backslash parsing differs from WhatWG URL standard; enables auth bypass in web apps using `dart:html`. Backslash treated as path separator in browser but not in Dart URI parser. | Dart 2.18.2 / Flutter 3.3.3 |
| CVE-2022-0451 | Moderate (6.5) | Dart SDK `dart:io` HttpClient | Authorization, cookie, and `www-authenticate` headers forwarded on cross-origin HTTP redirects, exposing credentials to redirect target. | Dart 2.16.0 / Flutter 2.10.0 |
| CVE-2021-22568 | Moderate (6.5) | Dart SDK pub client | OAuth2 access tokens for pub.dev leaked to third-party package repositories when publishing via `PUB_HOSTED_URL` or `--server`. | Dart 2.15.0 |
| CVE-2021-31402 | High (7.5) | `dio` package ≤4.0.6 | CRLF injection via attacker-controlled HTTP method string in `dio_mixin.dart`. Allows HTTP request splitting and response poisoning. | dio 5.0.0 |
| CVE-2023-41387 | Critical (9.1) | `flutter_downloader` ≤1.11.1 | SQL injection via malicious server-crafted download URL; allows session token theft and arbitrary file write inside app container (iOS). | 1.11.2 |
| CVE-2024-29887 | High (7.4) | `serverpod_client` ≤1.2.5 | TLS certificate validation bypassed for all non-web HTTP clients via improper `badCertificateCallback` usage — classic MitM enablement. | serverpod 1.2.6 |
| CVE-2024-48915 | High (8.7) | `agent_dart` ≤1.0.0-dev.28 | Certificate delegation check skips `canister_ranges` validation; timestamp `/time` path unchecked, removing expiry enforcement. | 1.0.0-dev.29 |
| CVE-2024-54461 | High (7.1 NIST) | `file_selector_android` ≤0.5.1+11 | Unsanitized filenames from malicious document providers allow path traversal to overwrite internal app cache files. | 0.5.1+12 |
| CVE-2026-27704 | Low | Dart pub client ≤Dart 3.10.x | Zip slip / symlink traversal in `dart pub` package extraction — malicious pub cache package can write files outside `PUB_CACHE`. Only exploitable with malicious custom registries or git packages. | Dart 3.11.0 / Flutter 3.41.0 |
| GHSA-3hpf-ff72-j67p | Low (3.0) | `shared_preferences_android` ≤2.3.3 | Deserialization of special string prefixes allows arbitrary class instantiation; can lead to code execution if a malicious preferences file is placed on-device. | 2.3.4 |
| Zellic Research 2024 | Critical | Proton Wallet (Flutter) | `dart:math` `Random()` used for BIP39 mnemonic generation; 32-bit seed allows full keyspace exhaustion in ~16 minutes; all wallets with affected build are recoverable by brute force. | Vendor patch (2024) |

---

## Security Checklist

### Cryptography and Randomness
- [ ] All cryptographic operations use `Random.secure()`, not `Random()`
- [ ] AES-GCM (preferred) or AES-CBC with unique random IV/nonce per operation
- [ ] No AES-ECB mode used anywhere
- [ ] Nonces/IVs are never reused with the same key
- [ ] Passwords hashed with bcrypt (≥cost 12) or Argon2id — not MD5/SHA-1/SHA-256
- [ ] Encryption keys derived via PBKDF2 or Argon2 if derived from passwords
- [ ] TLS 1.2+ enforced for all network connections

### Secrets Management
- [ ] No API keys, passwords, or secrets in source code or `--dart-define`
- [ ] Secrets retrieved at runtime from authenticated backend, not from binary
- [ ] `flutter_secure_storage` used for all on-device secrets (tokens, keys, PII)
- [ ] No secrets in `SharedPreferences`, Hive box keys, or logs
- [ ] `pubspec.lock` committed to version control
- [ ] Gitleaks/TruffleHog running in pre-commit hooks

### Network Security
- [ ] `badCertificateCallback` never returns `true` unconditionally
- [ ] Certificate pinning implemented for high-value API endpoints
- [ ] All API URLs use `https://`; `http://` rejected at validation layer
- [ ] `dio` ≥5.0.0 used (fixes CVE-2021-31402 CRLF injection)
- [ ] Dart SDK ≥2.16.0 (fixes CVE-2022-0451 auth header leak on redirects)
- [ ] `android:usesCleartextTraffic="false"` in production manifest
- [ ] `NSAllowsArbitraryLoads` not set in production `Info.plist`

### Data Storage
- [ ] No sensitive data in `SharedPreferences` or unencrypted Hive boxes
- [ ] `flutter_secure_storage` used with `encryptedSharedPreferences: true` on Android
- [ ] Hive encryption keys stored in `flutter_secure_storage`, not hardcoded
- [ ] Database encrypted with `sqflite_sqlcipher` if it contains PII
- [ ] Deleted sensitive Hive entries followed by `box.compact()`

### Input Validation and Injection
- [ ] All sqflite queries use `?` parameterization (no string concatenation)
- [ ] `flutter_downloader` upgraded to ≥1.11.2 (fixes CVE-2023-41387)
- [ ] All file paths canonicalized and base-directory prefix verified
- [ ] No user input passed to `Process.run()` with `runInShell: true`
- [ ] All `jsonDecode()` results validated by type and semantic constraints

### Mobile Platform Security
- [ ] `FLAG_SECURE` set on Android for sensitive screens
- [ ] Privacy overlay applied on iOS `applicationWillResignActive`
- [ ] `android:allowBackup="false"` in manifest (or explicit backup rules)
- [ ] `android:debuggable="false"` in production manifest (auto-set in release build)
- [ ] Deep links use HTTPS App Links / Universal Links, not custom URL schemes
- [ ] All deep link parameters validated before use
- [ ] Biometric auth tied to hardware-backed key, not just boolean result

### WebView
- [ ] JavaScript disabled unless explicitly required
- [ ] `navigationDelegate` implemented with allowlisted origins
- [ ] `file://` and `javascript:` URIs blocked in navigation delegate
- [ ] No sensitive `JavascriptChannel` methods exposed to untrusted web content
- [ ] `webview_flutter` updated to current version

### Build and Supply Chain
- [ ] Release builds use `--obfuscate --split-debug-info=<dir>`
- [ ] Debug symbols artifact stored securely alongside release
- [ ] `dart pub audit` or `osv-scanner` runs in CI; blocks on CRITICAL/HIGH
- [ ] All new pub.dev dependencies reviewed (publisher, stars, last update, license)
- [ ] `shared_preferences_android` ≥2.3.4 (fixes GHSA-3hpf-ff72-j67p)
- [ ] `file_selector_android` ≥0.5.1+12 (fixes CVE-2024-54461)

### Logging
- [ ] No `print()` or `debugPrint()` with sensitive data
- [ ] All debug logging gated behind `kDebugMode` or `dart:developer` `log()`
- [ ] Crash reporting configured to redact PII before upload
- [ ] No exception messages containing credentials logged to crash reporters

---

## Tooling

| Tool | Purpose | Command |
|------|---------|---------|
| [dart pub audit](https://dart.dev/tools/pub/security-advisories) | Built-in: surfaces GitHub Advisory DB entries for all dependencies | `dart pub audit` |
| [osv-scanner](https://github.com/google/osv-scanner) | Cross-references `pubspec.lock` against OSV vulnerability database | `osv-scanner --lockfile pubspec.lock` |
| [flutter pub outdated](https://dart.dev/tools/pub/cmd/pub-outdated) | Shows outdated dependencies with available versions | `flutter pub outdated` |
| [Gitleaks](https://github.com/gitleaks/gitleaks) | Scans git history and staged files for hardcoded secrets | `gitleaks detect --source=.` |
| [TruffleHog](https://github.com/trufflesecurity/trufflehog) | Deep git history secret scanning with entropy analysis | `trufflehog git file://.` |
| [MobSF](https://github.com/MobSF/Mobile-Security-Framework-MobSF) | Static + dynamic analysis of Android APKs and iOS IPAs | `docker run -p 8000:8000 opensecurity/mobile-security-framework-mobsf` |
| [objection](https://github.com/sensepost/objection) | Runtime mobile exploration; test biometric bypass, storage access | `objection -g com.example.app explore` |
| [blutter](https://github.com/worawit/blutter) | Extracts Dart symbols and method names from Flutter AOT `libapp.so` | `python3 blutter.py libapp.so output/` |
| [flutter_jailbreak_detection](https://pub.dev/packages/flutter_jailbreak_detection) | Detect rooted/jailbroken devices at runtime | Add to `pubspec.yaml`; call at app start |
| [freeRASP](https://pub.dev/packages/freerasp) | Runtime Application Self-Protection; detects Frida, root, tampering | `dart pub add freerasp` |
| [dart_code_metrics](https://pub.dev/packages/dart_code_metrics) | Static analysis rules for Dart quality and security patterns | `dart run dart_code_metrics:metrics analyze lib` |
| [dependency_validator](https://pub.dev/packages/dependency_validator) | Checks for unused, missing, or insecure transitive dependencies | `dart pub global activate dependency_validator && dependency_validator` |
