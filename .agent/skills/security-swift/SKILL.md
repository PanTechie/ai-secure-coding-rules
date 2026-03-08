---
name: Swift Security
description: >
  Activate when writing or reviewing Swift or Swift/Vapor code involving
  force-unwrap (!)/try!/guard let optionals on user-controlled data, UnsafePointer/UnsafeMutableRawPointer/
  withUnsafeBytes memory operations, Codable/JSONDecoder/Decodable deserialization with privileged fields,
  @objc dynamic/KVC/performSelector: Objective-C bridging, CryptoKit AES.GCM/SHA256/SymmetricKey/
  CCKeyDerivationPBKDF cryptography, SecRandomCopyBytes, UserDefaults/@AppStorage/Keychain/
  NSFileProtectionComplete data storage, actor/Sendable/@MainActor Swift concurrency,
  WKWebView/evaluateJavaScript:/callAsyncJavaScript: WebView, onOpenURL/openURL deep links,
  Logger/os_log privacy:.public/.private logging, Vapor/Fluent SQLKit raw queries/\(bind:)/
  SQLIdentifier SQL, Leaf/#unsafeHTML template injection, Vapor JWT/JWTPayload/ExpirationClaim,
  HTTPHeaders CRLF/redirect, Swift Package Manager/Package.resolved/binaryTarget checksum supply chain.
  Also activate when the user mentions CVE, Vapor, SwiftUI security, actor isolation, ReDoS in Swift,
  swift-package-audit, osv-scanner, dsdump, or asks for a Swift security review.
---

## Use this skill when

Activate when writing or reviewing Swift or Swift/Vapor code involving
force-unwrap (!)/try!/guard let optionals on user-controlled data, UnsafePointer/UnsafeMutableRawPointer/
withUnsafeBytes memory operations, Codable/JSONDecoder/Decodable deserialization with privileged fields,
@objc dynamic/KVC/performSelector: Objective-C bridging, CryptoKit AES.GCM/SHA256/SymmetricKey/
CCKeyDerivationPBKDF cryptography, SecRandomCopyBytes, UserDefaults/@AppStorage/Keychain/
NSFileProtectionComplete data storage, actor/Sendable/@MainActor Swift concurrency,
WKWebView/evaluateJavaScript:/callAsyncJavaScript: WebView, onOpenURL/openURL deep links,
Logger/os_log privacy:.public/.private logging, Vapor/Fluent SQLKit raw queries/\(bind:)/
SQLIdentifier SQL, Leaf/#unsafeHTML template injection, Vapor JWT/JWTPayload/ExpirationClaim,
HTTPHeaders CRLF/redirect, Swift Package Manager/Package.resolved/binaryTarget checksum supply chain.
Also activate when the user mentions CVE, Vapor, SwiftUI security, actor isolation, ReDoS in Swift,
swift-package-audit, osv-scanner, dsdump, or asks for a Swift security review.

## Instructions

Read the `rules.md` file in this skill directory and apply those security rules to all code analysis and generation tasks.
