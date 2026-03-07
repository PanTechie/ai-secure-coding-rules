---
name: Objective-C Security
description: >
  Activate when writing or reviewing Objective-C or Objective-C++ code involving
  strcpy/strcat/sprintf/memcpy C string operations, NSLog/NSString stringWithFormat: with user input,
  NSKeyedUnarchiver/unarchiveObjectWithData: deserialization, NSPredicate predicateWithFormat: injection,
  setValue:forKeyPath:/valueForKeyPath: KVC with user input, NSClassFromString/NSSelectorFromString/performSelector:
  dynamic dispatch, NSUserDefaults/plist/NSFileManager data storage, SecItemAdd/SecItemCopyMatching Keychain,
  kSecAttrAccessible values, didReceiveAuthenticationChallenge TLS validation, NSAllowsArbitraryLoads ATS,
  FMDB/sqlite3 SQL queries, UIWebView/WKWebView/evaluateJavaScript:, openURL:/deep links,
  CC_MD5/CC_SHA1/kCCAlgorithmDES/kCCOptionECBMode/arc4random cryptography, SecRandomCopyBytes,
  LAContext/evaluatePolicy: biometrics, __bridge/__bridge_transfer Core Foundation bridging,
  CocoaPods/Podfile.lock supply chain, PT_DENY_ATTACH/get-task-allow entitlements.
  Also activate when the user mentions CVE, NSKeyedUnarchiver gadget chain, KVC injection,
  method swizzling, jailbreak detection, class-dump, Frida, MobSF, or asks for an Objective-C security review.
---

## Use this skill when

Activate when writing or reviewing Objective-C or Objective-C++ code involving
strcpy/strcat/sprintf/memcpy C string operations, NSLog/NSString stringWithFormat: with user input,
NSKeyedUnarchiver/unarchiveObjectWithData: deserialization, NSPredicate predicateWithFormat: injection,
setValue:forKeyPath:/valueForKeyPath: KVC with user input, NSClassFromString/NSSelectorFromString/performSelector:
dynamic dispatch, NSUserDefaults/plist/NSFileManager data storage, SecItemAdd/SecItemCopyMatching Keychain,
kSecAttrAccessible values, didReceiveAuthenticationChallenge TLS validation, NSAllowsArbitraryLoads ATS,
FMDB/sqlite3 SQL queries, UIWebView/WKWebView/evaluateJavaScript:, openURL:/deep links,
CC_MD5/CC_SHA1/kCCAlgorithmDES/kCCOptionECBMode/arc4random cryptography, SecRandomCopyBytes,
LAContext/evaluatePolicy: biometrics, __bridge/__bridge_transfer Core Foundation bridging,
CocoaPods/Podfile.lock supply chain, PT_DENY_ATTACH/get-task-allow entitlements.
Also activate when the user mentions CVE, NSKeyedUnarchiver gadget chain, KVC injection,
method swizzling, jailbreak detection, class-dump, Frida, MobSF, or asks for an Objective-C security review.

## Instructions

Read the `rules.md` file in this skill directory and apply those security rules to all code analysis and generation tasks.
