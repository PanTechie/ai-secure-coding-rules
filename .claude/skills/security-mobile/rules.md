# 🛡️ Code Security Rules — Mobile Applications

> **Version:** 1.0.0
> **Based on:** [OWASP Mobile Top 10:2024](https://owasp.org/www-project-mobile-top-10/) + [OWASP MASVS 2.1](https://mas.owasp.org/MASVS/) + [OWASP MASTG](https://mas.owasp.org/MASTG/)
> **Last updated:** February 2026
> **Applies to:** Android (Kotlin/Java), iOS (Swift/Objective-C), React Native, Flutter, and other mobile frameworks.
> **Usage:** Place this file in `.claude/rules/` in your repository.

---

## General Instructions

When writing, reviewing, or refactoring **mobile application code**, apply all rules in this document. Each section is organized by MASVS control group and maps to the corresponding Mobile Top 10 risk(s). Rules include platform-specific guidance for Android and iOS.

**Key principle:** Mobile apps run on untrusted devices. Unlike server-side code, the binary is in the attacker's hands. Every client-side control can be bypassed — enforce security server-side and treat the client as hostile.

---

## MASVS-STORAGE — Secure Data Storage

> **Mobile Top 10 mapping:** M9 (Insecure Data Storage)

### Mandatory Rules

- **Never store sensitive data in plaintext** — Credentials, tokens, PII, financial data, and health data must be encrypted at rest. Use platform-provided secure storage: Android Keystore + EncryptedSharedPreferences / EncryptedFile, or iOS Keychain with appropriate protection classes (`kSecAttrAccessibleWhenUnlockedThisDeviceOnly`). (`MASVS-STORAGE-1`)

- **Never log sensitive data** — Remove or redact credentials, tokens, PII, and financial data from all log statements (Logcat, os_log, NSLog, print). Use build-type checks or logging frameworks that strip logs in release builds. (`MASWE-0001`)

- **Exclude sensitive data from backups** — On Android, configure `android:allowBackup="false"` or use `backup_rules.xml` / `data_extraction_rules.xml` to exclude sensitive files. On iOS, set `isExcludedFromBackup = true` on sensitive file URLs. (`MASWE-0003`, `MASWE-0004`)

- **Protect data in external/shared storage** — On Android, never write sensitive data to external storage. Use internal storage (app sandbox) with Scoped Storage. On iOS, use the app sandbox and appropriate Data Protection classes. (`MASWE-0007`)

- **Clear sensitive data from memory** — Zero out sensitive byte arrays, strings, and buffers after use. Avoid keeping decrypted secrets in memory longer than necessary. (`MASWE-0118`)

- **Prevent UI data leakage** — Disable keyboard caching/autocomplete for sensitive input fields (passwords, credit cards). Use `android:inputType="textNoSuggestions|textPassword"` or `textContentType = .oneTimeCode` / `autocorrectionType = .no` on iOS. Prevent sensitive data in screenshots by using `FLAG_SECURE` (Android) or hiding content in `applicationWillResignActive` (iOS). (`MASWE-0053`, `MASWE-0055`)

- **Protect notifications** — Never include sensitive data (OTP codes, account balances, message previews) in notification content visible on lock screen. Use `VISIBILITY_PRIVATE` on Android or `hiddenPreviewsBody` on iOS. (`MASWE-0054`)

### Platform Examples

```kotlin
// ✅ Android — EncryptedSharedPreferences (MASVS-STORAGE-1)
val masterKey = MasterKey.Builder(context)
    .setKeyScheme(MasterKey.KeyScheme.AES256_GCM)
    .build()

val securePrefs = EncryptedSharedPreferences.create(
    context, "secure_prefs", masterKey,
    EncryptedSharedPreferences.PrefKeyEncryptionScheme.AES256_SIV,
    EncryptedSharedPreferences.PrefValueEncryptionScheme.AES256_GCM
)
securePrefs.edit().putString("auth_token", token).apply()
```

```swift
// ✅ iOS — Keychain storage (MASVS-STORAGE-1)
let query: [String: Any] = [
    kSecClass as String: kSecClassGenericPassword,
    kSecAttrAccount as String: "auth_token",
    kSecValueData as String: token.data(using: .utf8)!,
    kSecAttrAccessible as String: kSecAttrAccessibleWhenUnlockedThisDeviceOnly
]
SecItemAdd(query as CFDictionary, nil)
```

```kotlin
// ✅ Android — Prevent screenshots of sensitive screens
window.setFlags(
    WindowManager.LayoutParams.FLAG_SECURE,
    WindowManager.LayoutParams.FLAG_SECURE
)
```

---

## MASVS-CRYPTO — Cryptography

> **Mobile Top 10 mapping:** M10 (Insufficient Cryptography)

### Mandatory Rules

- **Use platform-provided cryptographic APIs** — Android: use `javax.crypto` with Android Keystore; iOS: use CryptoKit or Security framework (SecKey). Avoid custom or third-party crypto implementations unless audited. (`MASVS-CRYPTO-1`)

- **No hardcoded cryptographic keys** — Never embed encryption keys, API secrets, or signing keys in source code, resources, or assets. Keys discoverable by decompiling the APK/IPA are compromised by definition. Store keys in Android Keystore / iOS Secure Enclave. (`MASWE-0013`)

- **Use approved algorithms only** — AES-256-GCM for symmetric encryption, SHA-256+ for hashing, ECDSA P-256+ or RSA-3072+ for asymmetric operations. Never use DES, 3DES, RC4, MD5, SHA-1 for security purposes, or ECB mode. (`MASWE-0020`, `MASWE-0021`, `MASWE-0023`)

- **Generate keys securely** — Use platform CSPRNG for key generation. On Android, use `KeyGenerator` with `KeyGenParameterSpec` bound to Keystore. On iOS, use `SecKeyCreateRandomKey` or CryptoKit. Never derive keys from weak sources (timestamps, device IDs). (`MASWE-0009`, `MASWE-0027`)

- **Use unique, random IVs** — Generate a fresh random IV/nonce for each encryption operation. Never reuse IVs with the same key. Store IV alongside ciphertext (it's not secret). (`MASWE-0022`)

- **Protect keys at rest** — Use hardware-backed key storage (Android Keystore with `setIsStrongBoxBacked(true)` where available, iOS Secure Enclave). Set key access constraints: user authentication required, biometric binding, non-exportable. (`MASWE-0014`, `MASVS-CRYPTO-2`)

### Platform Examples

```kotlin
// ✅ Android — AES-GCM with Keystore-backed key (MASVS-CRYPTO-1, MASVS-CRYPTO-2)
val keyGen = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, "AndroidKeyStore")
keyGen.init(
    KeyGenParameterSpec.Builder("my_key", KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT)
        .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
        .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
        .setKeySize(256)
        .setUserAuthenticationRequired(true)
        .setUserAuthenticationParameters(300, KeyProperties.AUTH_BIOMETRIC_STRONG)
        .build()
)
val secretKey = keyGen.generateKey()
val cipher = Cipher.getInstance("AES/GCM/NoPadding")
cipher.init(Cipher.ENCRYPT_MODE, secretKey)
val iv = cipher.iv  // Random IV generated automatically
val ciphertext = cipher.doFinal(plaintext)
```

```swift
// ✅ iOS — AES-GCM with CryptoKit (MASVS-CRYPTO-1)
import CryptoKit

let key = SymmetricKey(size: .bits256)
let sealedBox = try AES.GCM.seal(plaintext, using: key)
let ciphertext = sealedBox.combined!
// Decrypt
let openedBox = try AES.GCM.SealedBox(combined: ciphertext)
let decrypted = try AES.GCM.open(openedBox, using: key)
```

---

## MASVS-AUTH — Authentication and Authorization

> **Mobile Top 10 mapping:** M1 (Improper Credential Usage), M3 (Insecure Authentication/Authorization)

### Mandatory Rules

- **Never hardcode credentials or API keys** — No API keys, secrets, passwords, or tokens in source code, strings.xml, Info.plist, BuildConfig, or asset files. Use runtime-fetched configuration, environment-based injection, or secure server-side proxying. (`MASWE-0005`)

- **Enforce authentication server-side** — Client-side authentication checks (biometric, PIN) are UX conveniences, not security controls. Every sensitive API call must be authenticated and authorized by the backend. (`MASWE-0041`, `MASWE-0042`)

- **Implement secure biometric authentication** — Use cryptographic-bound biometrics (Android: `BiometricPrompt` with `CryptoObject`; iOS: `LAContext` with Keychain `kSecAccessControlBiometryCurrentSet`). Event-bound biometric checks (returning true/false) can be bypassed with Frida. Invalidate crypto keys when new biometrics are enrolled. (`MASWE-0044`, `MASWE-0046`)

- **Secure credential storage on device** — Store authentication tokens encrypted in Keystore/Keychain. Never store passwords locally. Use short-lived tokens with refresh capability. (`MASWE-0036`)

- **Transmit credentials only over TLS** — Never send credentials, tokens, or auth material over HTTP or insecure channels. (`MASWE-0037`)

- **Validate authentication tokens** — Verify JWT signatures, expiration, audience, and issuer on the client before trusting token content. But remember: ultimate validation must happen server-side. (`MASWE-0038`)

- **Implement step-up authentication** — Require re-authentication (biometric, PIN, MFA) before high-risk operations: payments, profile changes, password resets. (`MASWE-0029`)

- **Use platform authentication standards** — Follow OAuth 2.0 + PKCE for mobile auth flows. Use ASWebAuthenticationSession (iOS) or Custom Tabs (Android) for browser-based auth — never embedded WebViews. (`MASWE-0033`)

### Platform Examples

```kotlin
// ✅ Android — Cryptographic biometric authentication (MASVS-AUTH-2)
val cipher = getCipherFromKeystore("biometric_key") // Pre-configured Keystore cipher
val biometricPrompt = BiometricPrompt(activity, executor,
    object : BiometricPrompt.AuthenticationCallback() {
        override fun onAuthenticationSucceeded(result: BiometricPrompt.AuthenticationResult) {
            // Use result.cryptoObject.cipher to decrypt/sign — crypto-bound, not bypassable
            val decrypted = result.cryptoObject!!.cipher!!.doFinal(encryptedToken)
        }
    }
)
biometricPrompt.authenticate(promptInfo, BiometricPrompt.CryptoObject(cipher))
```

```swift
// ✅ iOS — Keychain with biometric protection (MASVS-AUTH-2)
let access = SecAccessControlCreateWithFlags(
    nil,
    kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
    [.biometryCurrentSet, .privateKeyUsage],  // Invalidates on new enrollment
    nil
)!
let query: [String: Any] = [
    kSecClass as String: kSecClassGenericPassword,
    kSecAttrAccount as String: "auth_token",
    kSecValueData as String: tokenData,
    kSecAttrAccessControl as String: access
]
```

---

## MASVS-NETWORK — Network Communication

> **Mobile Top 10 mapping:** M5 (Insecure Communication)

### Mandatory Rules

- **TLS for all connections** — All network communication must use TLS 1.2+. No cleartext HTTP traffic. On Android, set `android:usesCleartextTraffic="false"` in manifest and configure Network Security Config. On iOS, ensure App Transport Security (ATS) is enabled with no exceptions. (`MASWE-0050`, `MASVS-NETWORK-1`)

- **Validate TLS certificates properly** — Never override TLS certificate validation. Do not implement custom `TrustManager` that accepts all certificates, custom `HostnameVerifier` that accepts all hostnames, or `onReceivedSslError` that proceeds on errors. (`MASWE-0052`)

- **Implement certificate pinning** — Pin server certificates or public keys for connections to your own backend. On Android, use Network Security Config `<pin-set>` with backup pins. On iOS, use `URLSessionDelegate` with pinned certificates or use TrustKit. Include pin rotation strategy. (`MASWE-0047`, `MASVS-NETWORK-2`)

- **No open local ports** — Do not expose local server sockets or debugging interfaces. If local inter-process communication is needed, use platform IPC mechanisms instead of TCP sockets. (`MASWE-0051`)

- **Use platform networking APIs** — Use `OkHttp`/`Retrofit` (Android) or `URLSession` (iOS). Avoid low-level socket APIs that bypass platform security checks. (`MASWE-0049`)

### Platform Examples

```xml
<!-- ✅ Android — Network Security Config (MASVS-NETWORK-1, MASVS-NETWORK-2) -->
<!-- res/xml/network_security_config.xml -->
<network-security-config>
    <base-config cleartextTrafficPermitted="false">
        <trust-anchors>
            <certificates src="system" />
        </trust-anchors>
    </base-config>
    <domain-config>
        <domain includeSubdomains="true">api.myapp.com</domain>
        <pin-set expiration="2026-06-01">
            <pin digest="SHA-256">AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=</pin>
            <pin digest="SHA-256">BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB=</pin><!-- backup -->
        </pin-set>
    </domain-config>
</network-security-config>
```

```swift
// ✅ iOS — Certificate pinning with URLSession (MASVS-NETWORK-2)
func urlSession(_ session: URLSession, didReceive challenge: URLAuthenticationChallenge,
                completionHandler: @escaping (URLSession.AuthChallengeDisposition, URLCredential?) -> Void) {
    guard let serverTrust = challenge.protectionSpace.serverTrust,
          let serverCert = SecTrustGetCertificateAtIndex(serverTrust, 0) else {
        completionHandler(.cancelAuthenticationChallenge, nil)
        return
    }
    let serverKey = SecCertificateCopyKey(serverCert)
    let pinnedKey = loadPinnedPublicKey()
    if serverKey == pinnedKey {
        completionHandler(.useCredential, URLCredential(trust: serverTrust))
    } else {
        completionHandler(.cancelAuthenticationChallenge, nil)
    }
}
```

---

## MASVS-PLATFORM — Platform Interaction

> **Mobile Top 10 mapping:** M8 (Security Misconfiguration)

### Mandatory Rules

- **Secure IPC mechanisms** — On Android, use `exported="false"` for Activities, Services, BroadcastReceivers, and ContentProviders that are not needed externally. Use explicit Intents. Protect exported components with custom permissions. On iOS, validate input from URL schemes and Universal Links. (`MASWE-0059`, `MASWE-0062`–`MASWE-0066`)

- **Secure WebViews** — Disable JavaScript in WebViews unless strictly necessary. Disable file access and content provider access. Never expose native Java/Swift objects via `addJavascriptInterface` / `WKScriptMessageHandler` to untrusted content. Disable WebView debugging in production. (`MASWE-0068`–`MASWE-0074`)

- **Validate deep links** — Validate all parameters from deep links / Universal Links / App Links before processing. Treat deep link parameters as untrusted input. Use HTTPS App Links (Android) and Universal Links (iOS) instead of custom URL schemes when possible. (`MASWE-0058`)

- **Protect against tapjacking/overlay attacks** — On Android, use `filterTouchesWhenObscured="true"` on sensitive Views or check `MotionEvent.FLAG_WINDOW_IS_OBSCURED`. (`MASWE-0056`)

- **Request minimum permissions** — Follow the principle of least privilege. Only request permissions that are strictly necessary. Request them at runtime when needed, not upfront. Provide rationale before each permission request. (`MASWE-0117`)

- **Disable debuggable flag** — Ensure `android:debuggable="false"` in release builds. Disable WebView remote debugging with `WebView.setWebContentsDebuggingEnabled(false)`. On iOS, verify `get-task-allow` entitlement is disabled in release profiles. (`MASWE-0067`, `MASWE-0074`)

- **Protect clipboard/pasteboard** — Don't copy sensitive data to clipboard. If necessary, set an expiration and restrict to local device only. On iOS, use `UIPasteboard.general.setItems(items, options: [.localOnly: true, .expirationDate: ...])`. (`MASWE-0065`)

### Platform Examples

```xml
<!-- ✅ Android — Secure component configuration (MASVS-PLATFORM-1) -->
<activity
    android:name=".InternalActivity"
    android:exported="false" />

<provider
    android:name=".SecureContentProvider"
    android:exported="false"
    android:grantUriPermissions="false" />
```

```kotlin
// ✅ Android — Secure WebView configuration (MASVS-PLATFORM-2)
webView.settings.apply {
    javaScriptEnabled = false            // Enable ONLY if necessary
    allowFileAccess = false
    allowContentAccess = false
    allowFileAccessFromFileURLs = false
    allowUniversalAccessFromFileURLs = false
}
// NEVER in production:
// WebView.setWebContentsDebuggingEnabled(true)
```

---

## MASVS-CODE — Code Quality

> **Mobile Top 10 mapping:** M2 (Inadequate Supply Chain Security), M4 (Insufficient Input/Output Validation)

### Mandatory Rules

- **Validate all input from untrusted sources** — Treat data from deep links, Intents, IPC, network, clipboard, QR codes, NFC, and Bluetooth as untrusted. Validate type, length, format, and range. Sanitize before use in SQL, HTML, OS commands. (`MASWE-0079`–`MASWE-0088`)

- **Use parameterized queries** — Prevent SQL injection in local databases (SQLite, Room, Core Data). Never concatenate user input into SQL strings. (`MASWE-0086`)

- **Prevent unsafe deserialization** — Validate and restrict deserialization of data from untrusted sources. On Android, avoid `Serializable` / `Parcelable` from untrusted Intents without validation. On iOS, use `NSSecureCoding`. (`MASWE-0088`)

- **Keep dependencies updated** — Maintain an SBOM of all third-party libraries and SDKs. Monitor for known vulnerabilities (CVEs). Define and enforce remediation timelines. Use tools like Dependabot, Snyk, or OWASP Dependency-Check. (`MASWE-0076`)

- **Enable compiler security features** — Ensure PIE (Position Independent Executable), stack canaries, ARC (iOS), and NX (No eXecute) are enabled. On Android, enable R8/ProGuard minification. On iOS, compile with `-fstack-protector-all`. (`MASWE-0116`)

- **No dynamic code loading from untrusted sources** — Avoid `DexClassLoader` with untrusted paths, `dlopen` with untrusted libs, or evaluating JavaScript from untrusted sources. (`MASWE-0085`)

- **Implement forced updates** — Detect outdated app versions and require users to update for critical security patches. Use in-app update APIs (Android Play Core) or server-side version checks. (`MASWE-0075`)

- **Target latest platform versions** — Use the latest `targetSdkVersion` (Android) / deployment target (iOS) to benefit from the newest security features and restrictions. Set `minSdkVersion` high enough to avoid known OS vulnerabilities. (`MASWE-0077`, `MASWE-0078`)

### Platform Examples

```kotlin
// ❌ INSECURE — SQL injection in local database
val cursor = db.rawQuery("SELECT * FROM users WHERE id = '$userId'", null)

// ✅ SECURE — Parameterized query (MASWE-0086)
val cursor = db.rawQuery("SELECT * FROM users WHERE id = ?", arrayOf(userId))

// ✅ SECURE — Room DAO (parameterized by default)
@Dao
interface UserDao {
    @Query("SELECT * FROM users WHERE id = :userId")
    fun getUser(userId: String): User
}
```

```kotlin
// ✅ Android — Validate deep link input (MASVS-CODE-4)
override fun onCreate(savedInstanceState: Bundle?) {
    val uri = intent?.data ?: return
    val orderId = uri.getQueryParameter("order_id")
    if (orderId == null || !orderId.matches(Regex("^[a-zA-Z0-9]{8,20}$"))) {
        finish()  // Reject invalid input
        return
    }
    loadOrder(orderId)
}
```

---

## MASVS-RESILIENCE — Reverse Engineering and Tampering

> **Mobile Top 10 mapping:** M7 (Insufficient Binary Protections)

### Mandatory Rules

- **Obfuscate code** — Apply code obfuscation and shrinking for release builds. On Android, use R8 with aggressive obfuscation rules. On iOS, use commercial obfuscators or Swift's native name mangling. Remove debugging symbols from release binaries. (`MASWE-0089`, `MASWE-0093`)

- **Detect compromised environments** — Detect rooted (Android) / jailbroken (iOS) devices and respond appropriately (warn user, disable sensitive features, refuse to run). Use multiple detection techniques to resist bypass. (`MASWE-0097`)

- **Implement integrity verification** — Verify app signature and integrity at runtime. On Android, use Play Integrity API. On iOS, verify the app receipt and code signing. Detect repackaged or modified APKs/IPAs. (`MASWE-0104`, `MASWE-0106`)

- **Detect debugging and instrumentation** — Detect attached debuggers (ptrace, TracerPid, sysctl), Frida, Xposed, Substrate, and other instrumentation frameworks. Respond by terminating or degrading sensitive functionality. (`MASWE-0101`, `MASWE-0102`)

- **Implement layered protection** — Don't rely on a single resilience technique. Combine obfuscation, integrity checks, environment detection, and anti-debugging in layered, variable, and unpredictable ways. (`MASVS-RESILIENCE-1` through `MASVS-RESILIENCE-4`)

- **Remove non-production artifacts** — Strip test code, debug endpoints, staging URLs, verbose logging, and development credentials from release builds. (`MASWE-0094`, `MASWE-0095`)

### Platform Examples

```kotlin
// ✅ Android — R8/ProGuard obfuscation config (MASVS-RESILIENCE-3)
// build.gradle.kts
android {
    buildTypes {
        release {
            isMinifyEnabled = true
            isShrinkResources = true
            proguardFiles(
                getDefaultProguardFile("proguard-android-optimize.txt"),
                "proguard-rules.pro"
            )
        }
    }
}
```

```kotlin
// ✅ Android — Root detection example (MASVS-RESILIENCE-1)
fun isDeviceCompromised(): Boolean {
    val indicators = listOf(
        File("/system/app/Superuser.apk").exists(),
        File("/system/xbin/su").exists(),
        File("/data/local/bin/su").exists(),
        System.getenv("PATH")?.split(":")?.any { File(it, "su").exists() } == true,
        Build.TAGS?.contains("test-keys") == true
    )
    return indicators.any { it }
}
```

---

## MASVS-PRIVACY — User Privacy

> **Mobile Top 10 mapping:** M6 (Inadequate Privacy Controls)

### Mandatory Rules

- **Minimize data collection** — Collect only data necessary for the app's functionality. Apply data minimization, anonymization, and pseudonymization where possible. (`MASWE-0109`)

- **No tracking without consent** — Do not use device identifiers (IMEI, MAC, Android ID, IDFA) for tracking without explicit user consent. Use platform-provided opt-in advertising IDs. Respect user opt-out preferences (App Tracking Transparency on iOS, ad personalization on Android). (`MASWE-0110`)

- **Transparent privacy practices** — Declare all data collection in app store privacy labels (App Privacy on iOS, Data Safety on Android). Maintain an accurate, accessible privacy policy. (`MASWE-0111`, `MASWE-0112`)

- **Implement user data controls** — Provide users ability to view, export, and delete their data. Implement data retention policies and automatic deletion. (`MASWE-0113`)

- **Obtain proper consent** — Implement clear, granular consent mechanisms. Consent must be freely given, specific, informed, and unambiguous. Don't bundle unrelated consents. Allow withdrawal of consent at any time. (`MASWE-0115`)

- **Minimize permission requests** — Request only necessary permissions. Use scoped storage, photo picker, and other permission-less alternatives where available. Reset unused permissions. (`MASWE-0117`)

- **Protect PII in network traffic** — Audit network traffic to ensure no undeclared PII is transmitted to analytics, ads, or third-party SDKs. (`MASWE-0108`)

---

## Cross-Cutting Concerns

### Supply Chain Security (Mobile Top 10: M2)

- **Vet third-party SDKs** — Review permissions, network behavior, and data collection of all SDKs before integration. Prefer open-source or audited libraries.
- **Pin SDK versions** — Use exact versions, not ranges. Verify checksums/signatures of downloaded dependencies.
- **Monitor SDK behavior** — Audit network traffic from third-party SDKs regularly. Use tools like Charles Proxy or mitmproxy to detect unexpected data exfiltration.
- **Maintain SBOM** — Keep an up-to-date Software Bill of Materials. Use `gradle dependencies` / `pod outdated` / `flutter pub outdated` regularly.

### Secure Build Pipeline

- **Sign releases properly** — On Android, use APK Signature Scheme v2+ (v3 recommended). On iOS, ensure proper code signing with distribution certificates.
- **Strip debug info** — Remove debugging symbols, source maps, and verbose error messages from release builds.
- **Automate security checks** — Integrate SAST (semgrep, MobSF), dependency scanning, and secret detection into CI/CD.

---

## Quick Checklist by Mobile Top 10

| #   | Risk                            | Key Question                                                    | MASVS Group      |
| --- | ------------------------------- | --------------------------------------------------------------- | ---------------- |
| M1  | Improper Credential Usage       | Any hardcoded API keys, secrets, or credentials?                | MASVS-AUTH       |
| M2  | Inadequate Supply Chain         | SDKs vetted? Dependencies up-to-date? SBOM maintained?          | MASVS-CODE       |
| M3  | Insecure Auth/Authz             | Auth enforced server-side? Biometrics crypto-bound?             | MASVS-AUTH       |
| M4  | Insufficient I/O Validation     | All untrusted input validated? SQL parameterized?               | MASVS-CODE       |
| M5  | Insecure Communication          | TLS everywhere? Cert pinning? No cleartext?                     | MASVS-NETWORK    |
| M6  | Inadequate Privacy              | Minimal data collection? Consent obtained? Tracking disclosed?  | MASVS-PRIVACY    |
| M7  | Insufficient Binary Protections | Obfuscated? Root/jailbreak detection? Integrity checks?         | MASVS-RESILIENCE |
| M8  | Security Misconfiguration       | Debuggable=false? WebView secured? Components exported=false?   | MASVS-PLATFORM   |
| M9  | Insecure Data Storage           | Keystore/Keychain used? No plaintext storage? Backups excluded? | MASVS-STORAGE    |
| M10 | Insufficient Cryptography       | Approved algorithms? No hardcoded keys? Hardware-backed?        | MASVS-CRYPTO     |

---

## Platform-Specific Cheat Sheet

### Android Security Essentials

| Area     | Must Do                                               | Must Avoid                                              |
| -------- | ----------------------------------------------------- | ------------------------------------------------------- |
| Storage  | EncryptedSharedPreferences, Room + SQLCipher          | SharedPreferences for secrets, external storage for PII |
| Keystore | `KeyGenParameterSpec` + StrongBox                     | Hardcoded keys, keys in assets/raw                      |
| Network  | Network Security Config, `usesCleartextTraffic=false` | Custom TrustManager accepting all, HTTP URLs            |
| WebView  | `exported=false`, JS disabled, file access disabled   | `setWebContentsDebuggingEnabled(true)` in prod          |
| Build    | R8 minify + obfuscate, `debuggable=false`             | `debuggable=true`, test code in prod                    |
| Auth     | BiometricPrompt + CryptoObject                        | FingerprintManager (deprecated), boolean auth           |
| IPC      | Explicit intents, permission-protected components     | Implicit intents for sensitive data, exported=true      |

### iOS Security Essentials

| Area    | Must Do                                                    | Must Avoid                                   |
| ------- | ---------------------------------------------------------- | -------------------------------------------- |
| Storage | Keychain + proper accessibility class, Data Protection     | UserDefaults for secrets, plist for tokens   |
| Crypto  | CryptoKit, Secure Enclave for key storage                  | CommonCrypto with DES/MD5, hardcoded keys    |
| Network | ATS enabled (no exceptions), cert pinning                  | `NSAllowsArbitraryLoads = YES`, disabled ATS |
| WebView | WKWebView (not UIWebView), JS disabled by default          | Exposing native bridges to untrusted content |
| Build   | Strip symbols, disable `get-task-allow` in release         | Debug entitlements in production             |
| Auth    | LAContext + Keychain `kSecAccessControlBiometryCurrentSet` | `evaluatePolicy` without crypto binding      |
| IPC     | Validate Universal Link parameters, restrict URL schemes   | Processing deep links without validation     |

---

## Testing Tools Reference

| Purpose            | Android                       | iOS                            | Cross-platform         |
| ------------------ | ----------------------------- | ------------------------------ | ---------------------- |
| Static Analysis    | semgrep, MobSF, Android Lint  | semgrep, MobSF, Xcode Analyzer | SonarQube              |
| Dynamic Analysis   | Frida, Objection, Drozer      | Frida, Objection, Cycript      | Burp Suite, mitmproxy  |
| Dependency Scan    | Gradle dependency-check, Snyk | CocoaPods audit, Snyk          | OWASP Dependency-Check |
| Binary Analysis    | jadx, apktool, dex2jar        | Hopper, class-dump, r2         | Ghidra                 |
| Network Testing    | Charles, mitmproxy            | Charles, Proxyman              | Wireshark              |
| Vulnerability Scan | AppSweep, NowSecure           | AppSweep, NowSecure            | MobSF                  |

---

## References

- [OWASP Mobile Top 10:2024](https://owasp.org/www-project-mobile-top-10/2023-risks/)
- [OWASP MASVS 2.1](https://mas.owasp.org/MASVS/)
- [OWASP MASTG (Mobile Application Security Testing Guide)](https://mas.owasp.org/MASTG/)
- [OWASP MASWE (Mobile Application Security Weakness Enumeration)](https://mas.owasp.org/MASWE/)
- [OWASP MAS Checklist](https://mas.owasp.org/checklists/)
- [OWASP Cheat Sheet Series — MASVS Index](https://cheatsheetseries.owasp.org/IndexMASVS.html)
- [Android Security Best Practices](https://developer.android.com/topic/security/best-practices)
- [Apple Platform Security Guide](https://support.apple.com/guide/security/)

---

## License

This document is released under [CC BY-SA 4.0](https://creativecommons.org/licenses/by-sa/4.0/). Based on the work of the [OWASP Foundation](https://owasp.org/).
