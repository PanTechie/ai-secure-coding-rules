---
name: Angular Security
description: >
  Activate when writing or reviewing Angular code involving bypassSecurityTrust*/DomSanitizer XSS sinks,
  [innerHTML]/CVE-2024-21490, URL sanitization, HttpClientXsrfModule CSRF, Route Guard client-side auth,
  Angular Universal SSR TransferState XSS, environment file secret leaks, HTTP interceptor token scope,
  ReDoS in built-in pipes (CVE-2023-26116/26117/26118), open redirect via Router,
  ngCspNonce CSP, NgRx/state management sensitive data, angular-oauth2-oidc PKCE,
  Service Worker cache security, production build hardening (disableDebugTools/sourceMap:false).
  Also activate when the user mentions CVE-2024-21490, CVE-2023-26117, CVE-2023-26116,
  bypassSecurityTrust, DomSanitizer, Angular Universal, NgRx, OIDC, or asks for an Angular security review.
---

## Use this skill when

Activate when writing or reviewing Angular code involving bypassSecurityTrust*/DomSanitizer XSS sinks,
[innerHTML]/CVE-2024-21490, URL sanitization, HttpClientXsrfModule CSRF, Route Guard client-side auth,
Angular Universal SSR TransferState XSS, environment file secret leaks, HTTP interceptor token scope,
ReDoS in built-in pipes (CVE-2023-26116/26117/26118), open redirect via Router,
ngCspNonce CSP, NgRx/state management sensitive data, angular-oauth2-oidc PKCE,
Service Worker cache security, production build hardening (disableDebugTools/sourceMap:false).
Also activate when the user mentions CVE-2024-21490, CVE-2023-26117, CVE-2023-26116,
bypassSecurityTrust, DomSanitizer, Angular Universal, NgRx, OIDC, or asks for an Angular security review.

## Instructions

Read the `rules.md` file in this skill directory and apply those security rules to all code analysis and generation tasks.
