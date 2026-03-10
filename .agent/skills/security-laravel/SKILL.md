---
name: Laravel Security
description: >
  Activate when writing or reviewing Laravel code involving whereRaw/selectRaw/orderByRaw SQL injection,
  Eloquent mass assignment ($fillable/$guarded/forceFill), Blade {!! !!} XSS/HTMLPurifier,
  @csrf/VerifyCsrfToken CSRF, Auth::attempt session fixation/throttleLogins, Gates/Policies IDOR,
  IFormFile/store() path traversal/MIME validation, APP_DEBUG/APP_KEY/env() secrets,
  redirect()->to() open redirect (CVE-2024-52301), Http::get() SSRF, exec()/Process command injection,
  unserialize() POP chains, queue job payload secrets, Sanctum/Passport token security,
  RateLimiter::for() brute-force, security headers middleware, Ignition RCE (CVE-2021-3129).
  Also activate when user mentions Eloquent, Blade, Fortify, Breeze, Jetstream, Sanctum, Passport,
  Livewire, mews/purifier, spatie/laravel-csp, Enlightn, roave/security-advisories,
  or asks for a Laravel security review.
---

## Use this skill when

Activate when writing or reviewing Laravel code involving whereRaw/selectRaw/orderByRaw SQL injection,
Eloquent mass assignment ($fillable/$guarded/forceFill), Blade {!! !!} XSS/HTMLPurifier,
@csrf/VerifyCsrfToken CSRF, Auth::attempt session fixation/throttleLogins, Gates/Policies IDOR,
IFormFile/store() path traversal/MIME validation, APP_DEBUG/APP_KEY/env() secrets,
redirect()->to() open redirect (CVE-2024-52301), Http::get() SSRF, exec()/Process command injection,
unserialize() POP chains, queue job payload secrets, Sanctum/Passport token security,
RateLimiter::for() brute-force, security headers middleware, Ignition RCE (CVE-2021-3129).
Also activate when user mentions Eloquent, Blade, Fortify, Breeze, Jetstream, Sanctum, Passport,
Livewire, mews/purifier, spatie/laravel-csp, Enlightn, roave/security-advisories,
or asks for a Laravel security review.

## Instructions

Read the `rules.md` file in this skill directory and apply those security rules to all code analysis and generation tasks.
