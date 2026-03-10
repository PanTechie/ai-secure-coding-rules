---
name: ASP.NET Core Security
description: >
  Activate when writing or reviewing ASP.NET Core code involving middleware pipeline order
  (UseAuthentication/UseAuthorization), ASP.NET Core Identity lockout/password policy,
  authorization policies/IAuthorizationService/resource-based IDOR, Data Protection API key ring,
  ValidateAntiForgeryToken/SameSite CSRF, model binding over-posting/[Bind]/[BindNever],
  FromSqlRaw/FromSqlInterpolated EF Core SQL injection, CORS AllowAnyOrigin misconfiguration,
  security headers (HSTS/CSP/X-Frame-Options), RateLimiter (.NET 7+), IFormFile path traversal,
  SignalR Hub authentication/WsGuard, Blazor MarkupString XSS/NavigationManager open redirect,
  Minimal API RequireAuthorization, OpenIdConnect PKCE/state/nonce, Swagger in production,
  CVE-2024-35264, CVE-2023-33170, CVE-2024-43483, CVE-2024-43485.
  Also activate when user mentions AddDefaultIdentity, ConfigureApplicationCookie, UseHsts,
  AddRateLimiter, MapHub, IDataProtector, AddAuthorization, or asks for an ASP.NET Core security review.
allowed-tools: Read
---

Read the `rules.md` file in this skill directory and apply those security rules to all code analysis and generation tasks.
