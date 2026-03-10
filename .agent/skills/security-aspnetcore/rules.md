# 🌐 ASP.NET Core Security Rules

> **Standard:** Secure coding rules for ASP.NET Core applications (.NET 6/7/8/9), covering the middleware pipeline, authentication, authorization, Data Protection API, anti-forgery, model binding, Entity Framework Core, SignalR, Blazor, gRPC, and Minimal APIs.
> **Sources:** Microsoft ASP.NET Core Security Documentation, OWASP .NET Security Cheat Sheet, CWE/MITRE, NVD/CVE Database, Microsoft Security Response Center (MSRC) Advisories, Snyk .NET Advisories
> **Version:** 1.0.0
> **Last updated:** March 2026
> **Scope:** ASP.NET Core framework patterns — middleware pipeline, Identity, authorization policies, Data Protection, model binding, EF Core, SignalR, Blazor, Minimal APIs, gRPC. C# language rules are in `code-security-csharp.md`.

---

## General Instructions

Apply these rules to all ASP.NET Core code generation, review, and refactoring tasks. ASP.NET Core's middleware pipeline is order-dependent — authentication middleware must precede authorization middleware, which must precede endpoint middleware. Many vulnerabilities stem from incorrect middleware order, overly permissive defaults (AllowAnyOrigin, missing anti-forgery, wildcard CORS), or relying on client-supplied data for authorization decisions. Always verify the complete request lifecycle when reviewing security-sensitive code.

---

## 1. Middleware Pipeline Order

**Vulnerability:** ASP.NET Core middleware executes in registration order. Placing `UseAuthorization()` before `UseAuthentication()` means the `HttpContext.User` is never populated — all `[Authorize]` checks pass as anonymous. Placing `UseCors()` after `UseRouting()` or endpoint middleware can cause preflight responses to bypass CORS checks.

**References:** CWE-284, CWE-862, OWASP A01:2021

### Mandatory Rules

- **Always register middleware in the correct security order**: `UseHsts()` → `UseHttpsRedirection()` → `UseStaticFiles()` → `UseRouting()` → `UseCors()` → `UseAuthentication()` → `UseAuthorization()` → `MapControllers()`/`MapRazorPages()`/`MapHub()`.
- **Never place `UseAuthorization()` before `UseAuthentication()`** — `HttpContext.User` will be an unauthenticated `ClaimsPrincipal`.
- **Never place `UseCors()` after `MapControllers()`** — endpoint-level CORS metadata will be processed after the response has started.
- **Apply `UseExceptionHandler("/error")` in production and `UseDeveloperExceptionPage()` only in development** — the developer page exposes stack traces, source code, and environment variables.

```csharp
// ❌ INSECURE — Wrong middleware order; authorization runs before authentication
app.UseRouting();
app.UseAuthorization();       // User is always anonymous here
app.UseAuthentication();      // Too late
app.MapControllers();

// ✅ SECURE — Correct middleware pipeline
if (app.Environment.IsDevelopment())
    app.UseDeveloperExceptionPage();
else
    app.UseExceptionHandler("/error"); // safe generic error page

app.UseHsts();
app.UseHttpsRedirection();
app.UseStaticFiles();
app.UseRouting();
app.UseCors("AllowSpecificOrigins");  // before endpoint middleware
app.UseAuthentication();              // populate HttpContext.User
app.UseAuthorization();               // evaluate [Authorize] with authenticated user
app.UseAntiforgery();                 // .NET 8+ Minimal API antiforgery
app.MapControllers();
app.MapRazorPages();
```

---

## 2. Authentication — ASP.NET Core Identity Hardening

**Vulnerability:** Default ASP.NET Core Identity settings allow weak passwords (6 chars, no complexity), do not lock accounts after repeated failures, and do not require email confirmation — enabling brute-force and account enumeration attacks.

**References:** CWE-307, CWE-521, OWASP A07:2021

### Mandatory Rules

- **Configure strong password requirements**: minimum 12 characters, require uppercase, lowercase, digit, and non-alphanumeric.
- **Enable account lockout**: `MaxFailedAccessAttempts: 5`, `DefaultLockoutTimeSpan: 15 minutes`. Lockout applies after registration to prevent brute-force even on new accounts.
- **Require confirmed email** (`RequireConfirmedEmail: true`) before allowing login.
- **Use `IPasswordHasher<T>` with Argon2id** (via `PasswordHasherCompatibilityMode.IdentityV3`) rather than the default PBKDF2-SHA256 iteration count if your threat model requires it.
- **Never store plaintext passwords or use `UserManager.CreateAsync` without hashing** — Identity always hashes, but confirm no custom `IPasswordHasher` bypasses this.
- **Implement `IUserClaimsPrincipalFactory<T>`** to control which claims are embedded in the cookie — exclude sensitive database fields.

```csharp
// ❌ INSECURE — Weak Identity defaults
builder.Services.AddDefaultIdentity<ApplicationUser>()
    .AddEntityFrameworkStores<AppDbContext>();
// Password: min 6 chars, no lockout, no email confirmation

// ✅ SECURE — Hardened Identity configuration
builder.Services.AddIdentity<ApplicationUser, IdentityRole>(options =>
{
    // Password policy
    options.Password.RequiredLength          = 12;
    options.Password.RequireUppercase        = true;
    options.Password.RequireLowercase        = true;
    options.Password.RequireDigit            = true;
    options.Password.RequireNonAlphanumeric  = true;
    options.Password.RequiredUniqueChars     = 6;

    // Account lockout
    options.Lockout.DefaultLockoutTimeSpan   = TimeSpan.FromMinutes(15);
    options.Lockout.MaxFailedAccessAttempts  = 5;
    options.Lockout.AllowedForNewUsers       = true; // lockout applies immediately

    // User settings
    options.User.RequireUniqueEmail          = true;
    options.SignIn.RequireConfirmedEmail     = true;
    options.SignIn.RequireConfirmedAccount   = true;
})
.AddEntityFrameworkStores<AppDbContext>()
.AddDefaultTokenProviders();
```

---

## 3. Authorization — Policies, Resource-Based & Minimal API

**Vulnerability:** Relying solely on `[Authorize]` on controllers without resource-level checks allows authenticated users to access other users' data (IDOR). Using role strings directly instead of policy names scatters authorization logic. Minimal API endpoints without explicit `.RequireAuthorization()` are public by default.

**References:** CWE-284, CWE-285, OWASP API1:2023, OWASP A01:2021

### Mandatory Rules

- **Define named authorization policies** in `AddAuthorizationBuilder()` — never scatter inline role checks across the codebase.
- **Use `IAuthorizationService.AuthorizeAsync()` for resource-based authorization** — validate that the authenticated user owns the resource being accessed.
- **Deny by default in Minimal APIs**: call `.RequireAuthorization()` on every endpoint or configure a `FallbackPolicy` that requires authentication.
- **Never derive authorization from request body/query parameters** (e.g., `userId` in body) — always read identity from `HttpContext.User`.
- **Implement custom `IAuthorizationRequirement`** for complex business rules — keep policy logic testable and centralized.

```csharp
// ❌ INSECURE — IDOR: authorization based on URL param, not token identity
app.MapGet("/orders/{id}", async (int id, AppDbContext db) =>
{
    return await db.Orders.FindAsync(id); // any authenticated user can read any order
});

// ❌ INSECURE — Minimal API endpoint without auth (public by default)
app.MapPost("/admin/reset", AdminService.Reset);

// ✅ SECURE — Named policy + resource ownership check
builder.Services.AddAuthorizationBuilder()
    .AddPolicy("AdminOnly", policy => policy.RequireRole("Admin"))
    .AddPolicy("OwnsResource", policy =>
        policy.Requirements.Add(new ResourceOwnerRequirement()));

// Fallback: require auth on all endpoints
builder.Services.AddAuthorizationBuilder()
    .SetFallbackPolicy(new AuthorizationPolicyBuilder()
        .RequireAuthenticatedUser()
        .Build());

// Resource-based authorization in handler
app.MapGet("/orders/{id}", async (
    int id,
    ClaimsPrincipal user,
    IAuthorizationService authz,
    AppDbContext db) =>
{
    var order = await db.Orders.FindAsync(id);
    if (order is null) return Results.NotFound();

    var result = await authz.AuthorizeAsync(user, order, "OwnsResource");
    if (!result.Succeeded) return Results.Forbid();

    return Results.Ok(order);
}).RequireAuthorization(); // fallback + explicit for clarity

// ResourceOwnerRequirement handler
public class ResourceOwnerHandler : AuthorizationHandler<ResourceOwnerRequirement, Order>
{
    protected override Task HandleRequirementAsync(
        AuthorizationHandlerContext ctx,
        ResourceOwnerRequirement req,
        Order resource)
    {
        var userId = ctx.User.FindFirstValue(ClaimTypes.NameIdentifier);
        if (resource.UserId == userId)
            ctx.Succeed(req);
        return Task.CompletedTask;
    }
}
```

---

## 4. Data Protection API

**Vulnerability:** Using the default ASP.NET Core Data Protection with ephemeral keys (in-memory, per-process) means authentication cookies and anti-forgery tokens are invalidated on every restart, and cannot be shared across load-balanced instances. Storing the key ring in an unencrypted location allows an attacker with file system access to decrypt all protected data.

**References:** CWE-312, CWE-320, OWASP A02:2021

### Mandatory Rules

- **Persist the key ring** to a durable location — Azure Key Vault, AWS SSM, Redis, or an encrypted file share. Never use ephemeral in-memory keys in production.
- **Encrypt the key ring at rest** using `ProtectKeysWithAzureKeyVault()`, `ProtectKeysWithCertificate()`, or `ProtectKeysWithDpapi()` (Windows only).
- **Set `SetApplicationName()`** to the same string across all instances sharing the same key ring — prevents cross-application key reuse by default.
- **Configure key lifetime** (`SetDefaultKeyLifetime(TimeSpan.FromDays(90))`) and ensure automated rotation.
- **Use purpose strings** when creating `IDataProtector` — isolates payloads so a token for "PasswordReset" cannot be replayed in a "EmailConfirmation" context.

```csharp
// ❌ INSECURE — Ephemeral in-memory keys; invalidated on restart, not shared
builder.Services.AddDataProtection();

// ❌ INSECURE — Key ring stored unencrypted on disk
builder.Services.AddDataProtection()
    .PersistKeysToFileSystem(new DirectoryInfo("/var/keys"));

// ✅ SECURE — Azure Key Vault persistence + encryption (production)
builder.Services.AddDataProtection()
    .SetApplicationName("MyApp-Production")
    .PersistKeysToAzureBlobStorage(
        new Uri(builder.Configuration["DataProtection:BlobUri"]!),
        new DefaultAzureCredential())
    .ProtectKeysWithAzureKeyVault(
        new Uri(builder.Configuration["DataProtection:KeyVaultKeyUri"]!),
        new DefaultAzureCredential())
    .SetDefaultKeyLifetime(TimeSpan.FromDays(90));

// ✅ SECURE — Purpose strings isolate token payloads
public class TokenService(IDataProtectionProvider provider)
{
    private readonly IDataProtector _pwReset =
        provider.CreateProtector("MyApp.PasswordReset.v1");
    private readonly IDataProtector _emailConfirm =
        provider.CreateProtector("MyApp.EmailConfirmation.v1");
    // A PasswordReset token cannot be used for EmailConfirmation
}
```

---

## 5. CSRF — Anti-Forgery Protection

**Vulnerability:** ASP.NET Core Razor Pages auto-validates anti-forgery tokens via the `AutoValidateAntiforgeryTokenAttribute` applied globally, but MVC controllers require explicit `[ValidateAntiForgeryToken]` or a global filter. Minimal APIs require `ValidateAntiforgery()` in .NET 8+. APIs that accept `application/json` without checking `Content-Type` can be exploited via HTML forms with JSON-like payloads.

**References:** CWE-352, OWASP A01:2021

### Mandatory Rules

- **Apply `AutoValidateAntiforgeryTokenAttribute` globally** on MVC controllers — opt out only for explicit API endpoints with `[IgnoreAntiforgeryToken]`.
- **Use `SameSite=Strict` cookies** for session/auth cookies — this is the primary defense against CSRF.
- **For REST APIs consuming JSON**: validate the `Content-Type: application/json` header and reject `application/x-www-form-urlencoded` — HTML forms cannot set arbitrary Content-Type headers (CORS pre-flight blocks it).
- **Use `.NET 8+ `UseAntiforgery()` middleware** for Minimal APIs with form endpoints.
- **Never disable CSRF protection** on endpoints that perform state-changing operations authenticated by cookies.

```csharp
// ❌ INSECURE — MVC without global anti-forgery filter
builder.Services.AddControllersWithViews();
// POST endpoints have no CSRF protection

// ✅ SECURE — Global anti-forgery filter for MVC
builder.Services.AddControllersWithViews(options =>
{
    options.Filters.Add(new AutoValidateAntiforgeryTokenAttribute());
});

// ✅ SECURE — Razor Pages (anti-forgery is on by default, but make it explicit)
builder.Services.AddRazorPages(options =>
{
    options.Conventions.ConfigureFilter(new AutoValidateAntiforgeryTokenAttribute());
});

// ✅ SECURE — Minimal API with anti-forgery (.NET 8+)
builder.Services.AddAntiforgery();
// ...
app.UseAntiforgery();
app.MapPost("/account/update", async (
    [FromForm] UpdateProfileDto dto,
    HttpContext ctx,
    IAntiforgery antiforgery) =>
{
    await antiforgery.ValidateRequestAsync(ctx);
    // process dto
}).DisableAntiforgery(false); // explicit

// ✅ SECURE — Cookie configuration with SameSite=Strict
builder.Services.ConfigureApplicationCookie(options =>
{
    options.Cookie.HttpOnly  = true;
    options.Cookie.Secure    = CookieSecurePolicy.Always;
    options.Cookie.SameSite  = SameSiteMode.Strict;
    options.ExpireTimeSpan   = TimeSpan.FromHours(8);
    options.SlidingExpiration = true;
});
```

---

## 6. Model Binding & Over-Posting (Mass Assignment)

**Vulnerability:** ASP.NET Core model binding can bind any public property of the target model from the request, including fields like `IsAdmin`, `Role`, or `Id`. An attacker posting extra fields can escalate privileges or modify records they don't own.

**References:** CWE-915, OWASP A04:2021

### Mandatory Rules

- **Use View Models or DTOs** for all controller actions — never bind directly to database entities.
- **Use `[Bind("Prop1,Prop2")]`** on model parameters or `[BindNever]` on entity properties that should never be bound from requests.
- **Explicitly map** from DTO to entity in the service/application layer — never `_context.Entry(model).State = EntityState.Modified` with a model received from the client.
- **Never use `TryUpdateModelAsync(entity)` with a database entity** without an explicit include list.

```csharp
// ❌ INSECURE — Direct entity binding; attacker posts { "IsAdmin": true }
[HttpPost]
public async Task<IActionResult> UpdateProfile(ApplicationUser user)
{
    _context.Update(user); // IsAdmin, Role, Id all overwritten
    await _context.SaveChangesAsync();
    return Ok();
}

// ❌ INSECURE — TryUpdateModelAsync without explicit field list
await TryUpdateModelAsync(dbUser, prefix: "",
    u => u.DisplayName, u => u.Bio, u => u.IsAdmin); // IsAdmin bindable

// ✅ SECURE — DTO with explicit mapping
public class UpdateProfileDto
{
    [StringLength(100)] public string DisplayName { get; set; } = "";
    [StringLength(500)] public string Bio { get; set; } = "";
    // IsAdmin, Role, Id — NOT in DTO
}

[HttpPost("profile")]
public async Task<IActionResult> UpdateProfile(
    UpdateProfileDto dto,
    ClaimsPrincipal user)
{
    var userId = user.FindFirstValue(ClaimTypes.NameIdentifier)!;
    var dbUser = await _userManager.FindByIdAsync(userId)
        ?? throw new NotFoundException();

    dbUser.DisplayName = dto.DisplayName;
    dbUser.Bio = dto.Bio;
    // IsAdmin unchanged — never touched by model binding
    await _userManager.UpdateAsync(dbUser);
    return Ok();
}
```

---

## 7. Entity Framework Core — Raw SQL & Query Security

**Vulnerability:** `FromSqlRaw()` with string interpolation or `ExecuteSqlRaw()` with concatenated user input produce SQL injection. `FromSqlInterpolated()` is safe (parameterized), but developers frequently confuse the two. Additionally, including sensitive navigation properties in LINQ projections can expose data unintentionally.

**References:** CWE-89, OWASP A03:2021

### Mandatory Rules

- **Use `FromSqlInterpolated()` instead of `FromSqlRaw()`** for any query with parameters — the interpolated form uses `SqlParameter` under the hood.
- **Never use `FromSqlRaw()` or `ExecuteSqlRaw()` with string concatenation or `$""` interpolation** — these pass the interpolated string directly as SQL.
- **Use EF Core LINQ** (`Where()`, `Select()`, `OrderBy()`) wherever possible — EF Core generates parameterized SQL automatically.
- **Project to DTOs in LINQ** — never return full entity graphs from API endpoints; exclude sensitive properties (`PasswordHash`, `SecurityStamp`, etc.).
- **Validate user-controlled sort/order fields** against an allowlist — EF Core `OrderBy()` with dynamic string columns can be exploited.

```csharp
// ❌ INSECURE — String interpolation in FromSqlRaw = SQL injection
string search = Request.Query["q"];
var users = db.Users.FromSqlRaw($"SELECT * FROM Users WHERE Name LIKE '%{search}%'");

// ❌ INSECURE — Concatenation in ExecuteSqlRaw
await db.Database.ExecuteSqlRawAsync(
    "DELETE FROM Orders WHERE Status = '" + status + "'");

// ✅ SECURE — FromSqlInterpolated (auto-parameterized)
string search = Request.Query["q"].ToString();
var users = db.Users.FromSqlInterpolated(
    $"SELECT * FROM Users WHERE Name LIKE {$"%{search}%"}");

// ✅ SECURE — EF Core LINQ (always parameterized)
var users = await db.Users
    .Where(u => EF.Functions.Like(u.Name, $"%{search}%"))
    .Select(u => new UserDto { Id = u.Id, Email = u.Email }) // no PasswordHash
    .ToListAsync();

// ✅ SECURE — Allowlist for dynamic sort
var allowedColumns = new HashSet<string> { "Name", "CreatedAt", "Email" };
if (!allowedColumns.Contains(sortBy)) sortBy = "CreatedAt";

var query = db.Users.OrderBy(u => EF.Property<object>(u, sortBy));
```

---

## 8. CORS Configuration

**Vulnerability:** `AllowAnyOrigin()` with `AllowCredentials()` is rejected by browsers but misleads developers into thinking credentials are safe. `AllowAnyOrigin()` without credentials still enables cross-site reads of JSON API responses. Reflecting the `Origin` header dynamically without validation allows all origins, including attacker-controlled ones.

**References:** CWE-346, OWASP A05:2021

### Mandatory Rules

- **Never use `AllowAnyOrigin().AllowCredentials()`** — this combination is blocked by browsers and indicates a design error.
- **Use named policies** (`AddPolicy("name")`) and reference them explicitly in `UseCors("name")` — never use the default unnamed policy.
- **Define explicit allowed origins** from configuration — never reflect the `Origin` header dynamically without validation.
- **Restrict allowed methods and headers** — avoid `AllowAnyMethod()` and `AllowAnyHeader()` for sensitive APIs.

```csharp
// ❌ INSECURE — AllowAnyOrigin with credentials (rejected by browsers, bad signal)
builder.Services.AddCors(options =>
    options.AddDefaultPolicy(policy =>
        policy.AllowAnyOrigin().AllowAnyMethod().AllowCredentials()));

// ❌ INSECURE — Reflecting Origin header (allows all origins)
app.Use(async (ctx, next) => {
    ctx.Response.Headers.Append("Access-Control-Allow-Origin",
        ctx.Request.Headers["Origin"]); // reflects attacker's origin
    await next();
});

// ✅ SECURE — Explicit named policy with configured origin allowlist
var allowedOrigins = builder.Configuration
    .GetSection("Cors:AllowedOrigins")
    .Get<string[]>() ?? [];

builder.Services.AddCors(options =>
{
    options.AddPolicy("AllowFrontend", policy =>
        policy
            .WithOrigins(allowedOrigins)  // explicit list from config
            .WithMethods("GET", "POST", "PUT", "DELETE", "PATCH")
            .WithHeaders("Content-Type", "Authorization")
            .AllowCredentials()
            .SetPreflightMaxAge(TimeSpan.FromMinutes(10)));
});

app.UseCors("AllowFrontend"); // named policy, before UseAuthentication
```

---

## 9. Security Headers

**Vulnerability:** ASP.NET Core does not set security headers by default. Without `Strict-Transport-Security`, `Content-Security-Policy`, `X-Frame-Options`, `X-Content-Type-Options`, and `Permissions-Policy`, responses are vulnerable to protocol downgrade, clickjacking, MIME sniffing, and cross-origin information leakage.

**References:** OWASP A05:2021, CWE-693, CWE-1021

### Mandatory Rules

- **Enable HSTS** via `app.UseHsts()` in production — configure `preload: true`, `includeSubDomains: true`, and `maxAge` ≥ 1 year.
- **Add `X-Content-Type-Options: nosniff`** on all responses to prevent MIME sniffing.
- **Add `X-Frame-Options: DENY`** unless the app is explicitly embedded — prevents clickjacking.
- **Configure a Content Security Policy** — start with `default-src 'self'` and tighten per route if needed.
- **Remove `Server` and `X-Powered-By` headers** — do not reveal technology stack details.
- **Use the `NetEscapades.AspNetCore.SecurityHeaders` NuGet package** or a custom middleware for header management.

```csharp
// ❌ INSECURE — No security headers; default ASP.NET Core response
// Server: Kestrel (or IIS)
// No X-Content-Type-Options, no X-Frame-Options, no CSP

// ✅ SECURE — Custom security header middleware
app.Use(async (context, next) =>
{
    context.Response.Headers.Append("X-Content-Type-Options",     "nosniff");
    context.Response.Headers.Append("X-Frame-Options",            "DENY");
    context.Response.Headers.Append("X-XSS-Protection",          "0"); // disabled; rely on CSP
    context.Response.Headers.Append("Referrer-Policy",            "strict-origin-when-cross-origin");
    context.Response.Headers.Append("Permissions-Policy",
        "accelerometer=(), camera=(), geolocation=(), microphone=()");
    context.Response.Headers.Append("Content-Security-Policy",
        "default-src 'self'; " +
        "script-src 'self'; " +
        "style-src 'self' 'unsafe-inline'; " +
        "img-src 'self' data: https:; " +
        "font-src 'self'; " +
        "object-src 'none'; " +
        "frame-ancestors 'none'; " +
        "upgrade-insecure-requests;");
    // Remove revealing headers
    context.Response.Headers.Remove("Server");
    context.Response.Headers.Remove("X-Powered-By");
    await next();
});

// ✅ SECURE — HSTS (production only)
builder.Services.AddHsts(options =>
{
    options.Preload           = true;
    options.IncludeSubDomains = true;
    options.MaxAge            = TimeSpan.FromDays(365);
});
```

---

## 10. Rate Limiting (ASP.NET Core 7+)

**Vulnerability:** Without rate limiting, ASP.NET Core endpoints are vulnerable to brute-force on login, credential stuffing, resource exhaustion, and enumeration attacks. The built-in `RateLimiter` (introduced in .NET 7) avoids third-party dependencies but must be configured with a distributed store for multi-instance deployments.

**References:** CWE-307, CWE-400, OWASP A04:2021

### Mandatory Rules

- **Register `AddRateLimiter()` and `UseRateLimiter()`** — the middleware must be added before `UseAuthorization()`.
- **Apply strict per-IP or per-user limits on authentication endpoints** — 5 attempts per minute on `/login`, `/forgot-password`, `/register`.
- **Use sliding window or token bucket policies** for authenticated API endpoints to prevent burst abuse.
- **Require a distributed backing store (Redis)** for rate limiting across multiple instances — in-process `MemoryCache` limits are per-instance.
- **Return `429 Too Many Requests`** with a `Retry-After` header — never silently drop requests.

```csharp
// ❌ INSECURE — No rate limiting on authentication endpoint
app.MapPost("/account/login", LoginHandler);

// ✅ SECURE — Built-in ASP.NET Core rate limiting (.NET 7+)
builder.Services.AddRateLimiter(options =>
{
    options.RejectionStatusCode = StatusCodes.Status429TooManyRequests;
    options.OnRejected = async (ctx, token) =>
    {
        ctx.HttpContext.Response.Headers.Append("Retry-After", "60");
        await ctx.HttpContext.Response.WriteAsync("Too many requests.", token);
    };

    // Strict limit for auth endpoints (per IP)
    options.AddFixedWindowLimiter("auth", policy =>
    {
        policy.Window            = TimeSpan.FromMinutes(1);
        policy.PermitLimit       = 5;
        policy.QueueProcessingOrder = QueueProcessingOrder.OldestFirst;
        policy.QueueLimit        = 0; // reject immediately, no queue
    });

    // General API limit (per authenticated user or IP)
    options.AddSlidingWindowLimiter("api", policy =>
    {
        policy.Window              = TimeSpan.FromSeconds(10);
        policy.PermitLimit         = 100;
        policy.SegmentsPerWindow   = 4;
        policy.QueueProcessingOrder = QueueProcessingOrder.OldestFirst;
        policy.QueueLimit          = 10;
    });
});

app.UseRateLimiter();

app.MapPost("/account/login", LoginHandler)
    .RequireRateLimiting("auth");

app.MapGroup("/api").RequireRateLimiting("api");
```

---

## 11. File Upload Security

**Vulnerability:** `IFormFile` exposes `FileName` and `ContentType` from the multipart header — both are attacker-controlled. Saving files using `FileName` directly enables path traversal. Trusting `ContentType` without magic-byte inspection allows malicious file uploads disguised as images.

**References:** CWE-434, CWE-22, OWASP A04:2021

### Mandatory Rules

- **Never use `IFormFile.FileName`** as the storage filename — use a cryptographically random name (e.g., `Guid.NewGuid()`).
- **Never trust `IFormFile.ContentType`** — validate file content by reading magic bytes.
- **Enforce maximum file size** via `RequestSizeLimitAttribute` and Kestrel/IIS configuration — do not rely solely on `IFormFile.Length`.
- **Store uploaded files outside the web root** — serve them via a controller endpoint that sets `Content-Disposition: attachment`.
- **Validate file extension against an allowlist** in addition to magic-byte inspection.

```csharp
// ❌ INSECURE — Original filename + ContentType trusted; stored in wwwroot
[HttpPost("upload")]
public async Task<IActionResult> Upload(IFormFile file)
{
    var path = Path.Combine("wwwroot/uploads", file.FileName); // path traversal!
    await using var stream = System.IO.File.Create(path);
    await file.CopyToAsync(stream);
    return Ok($"/uploads/{file.FileName}"); // served directly
}

// ✅ SECURE — UUID filename, magic bytes, size limit, outside web root
private static readonly Dictionary<string, byte[]> AllowedMagicBytes = new()
{
    { ".jpg",  [0xFF, 0xD8, 0xFF] },
    { ".png",  [0x89, 0x50, 0x4E, 0x47] },
    { ".pdf",  [0x25, 0x50, 0x44, 0x46] },
    { ".webp", [0x52, 0x49, 0x46, 0x46] },
};
private const long MaxFileSizeBytes = 5 * 1024 * 1024; // 5 MB

[HttpPost("upload")]
[RequestSizeLimit(MaxFileSizeBytes + 4096)] // header overhead
public async Task<IActionResult> Upload(IFormFile file)
{
    if (file.Length is 0 or > MaxFileSizeBytes)
        return BadRequest("Invalid file size.");

    var ext = Path.GetExtension(file.FileName).ToLowerInvariant();
    if (!AllowedMagicBytes.TryGetValue(ext, out var magic))
        return BadRequest("File type not allowed.");

    // Validate magic bytes
    var header = new byte[magic.Length];
    await using var peekStream = file.OpenReadStream();
    if (await peekStream.ReadAsync(header) < magic.Length
        || !header.SequenceEqual(magic))
        return BadRequest("File content does not match declared type.");

    // UUID filename — never use file.FileName
    var safeFilename = $"{Guid.NewGuid():N}{ext}";
    var uploadDir = Path.GetFullPath(_config["UploadPath"]!);
    var fullPath  = Path.Combine(uploadDir, safeFilename);

    // Extra: verify path stays within upload dir (belt-and-suspenders)
    if (!fullPath.StartsWith(uploadDir + Path.DirectorySeparatorChar))
        return BadRequest("Invalid path.");

    await using var dest = System.IO.File.Create(fullPath);
    await using var src  = file.OpenReadStream();
    await src.CopyToAsync(dest);

    return Ok(new { filename = safeFilename });
}
```

---

## 12. Cookie & Session Security

**Vulnerability:** Default cookie settings in ASP.NET Core do not enforce `Secure`, and `SameSite=Lax` allows cookies to be sent with top-level navigations — which can be exploited in CSRF attacks on older browsers. Session identifiers stored in cookies without `HttpOnly` are accessible to JavaScript, enabling XSS-based session hijacking.

**References:** CWE-614, CWE-384, CWE-1004, OWASP A07:2021

### Mandatory Rules

- **Set `HttpOnly = true`** on all authentication and session cookies — prevents JavaScript access.
- **Set `Secure = CookieSecurePolicy.Always`** — cookies never sent over HTTP.
- **Set `SameSite = SameSiteMode.Strict`** for session cookies — prevents cross-site submission.
- **Regenerate the session ID after login** (`HttpContext.Session` auto-generates; for Identity, sign out then sign in to rotate the cookie).
- **Set an absolute expiry** on session cookies — do not rely solely on browser session lifetime.
- **Never store sensitive data (PII, tokens, roles) in session** — store only the minimum identifier needed.

```csharp
// ❌ INSECURE — Default session cookie settings
builder.Services.AddSession();
// Cookie: no HttpOnly set explicitly, SameSite=Lax, no Secure, no expiry

// ✅ SECURE — Hardened session and auth cookie configuration
builder.Services.AddSession(options =>
{
    options.Cookie.Name       = "__Host-Session"; // __Host- prefix enforces Secure + path=/
    options.Cookie.HttpOnly   = true;
    options.Cookie.Secure     = CookieSecurePolicy.Always;
    options.Cookie.SameSite   = SameSiteMode.Strict;
    options.Cookie.IsEssential = true;
    options.IdleTimeout       = TimeSpan.FromMinutes(30);
});

builder.Services.ConfigureApplicationCookie(options =>
{
    options.Cookie.Name       = "__Host-Auth";
    options.Cookie.HttpOnly   = true;
    options.Cookie.Secure     = CookieSecurePolicy.Always;
    options.Cookie.SameSite   = SameSiteMode.Strict;
    options.ExpireTimeSpan    = TimeSpan.FromHours(8);
    options.SlidingExpiration = true;
    // Regenerate session after login (Identity does this via sign-in/sign-out)
    options.Events.OnSigningIn = ctx =>
    {
        ctx.Properties.IsPersistent = false; // don't persist beyond browser session by default
        return Task.CompletedTask;
    };
});
```

---

## 13. OpenID Connect & OAuth 2.0 Configuration

**Vulnerability:** Misconfigured OIDC/OAuth2 — missing PKCE, not validating `state` or `nonce`, accepting tokens from any issuer, or using `response_type=token` (implicit flow) — allows authorization code interception, CSRF on the OAuth callback, and token leakage via browser history.

**References:** CWE-287, CWE-352, OAuth 2.0 Security Best Current Practice (RFC 9700), OWASP A07:2021

### Mandatory Rules

- **Always use PKCE** (`UsePkce = true`) with Authorization Code flow — never use Implicit flow.
- **Validate `state` and `nonce` claims** — ASP.NET Core's OIDC middleware validates these automatically; do not disable validation.
- **Pin the `Authority`** from configuration and never accept tokens from dynamic issuers.
- **Set `SaveTokens = false`** unless you need to access tokens in the application — storing tokens in cookies increases cookie size and exposure surface.
- **Validate `aud` and `iss` claims** in `TokenValidationParameters`.
- **Never log tokens** — do not log `access_token`, `id_token`, or `refresh_token`.

```csharp
// ❌ INSECURE — No PKCE, tokens saved to cookie, any issuer accepted
builder.Services.AddAuthentication().AddOpenIdConnect("oidc", options =>
{
    options.Authority    = "https://idp.example.com";
    options.ClientId     = "myapp";
    options.ClientSecret = "hardcoded-secret"; // ❌
    options.SaveTokens   = true;
    options.UsePkce      = false; // ❌
});

// ✅ SECURE — PKCE + strict claim validation + secret from config
builder.Services.AddAuthentication(options =>
{
    options.DefaultScheme          = CookieAuthenticationDefaults.AuthenticationScheme;
    options.DefaultChallengeScheme = OpenIdConnectDefaults.AuthenticationScheme;
})
.AddCookie(cookie =>
{
    cookie.Cookie.HttpOnly = true;
    cookie.Cookie.Secure   = CookieSecurePolicy.Always;
    cookie.Cookie.SameSite = SameSiteMode.Lax; // Lax required for OIDC redirect
})
.AddOpenIdConnect("oidc", options =>
{
    options.Authority     = config.GetOrThrow("Oidc:Authority");
    options.ClientId      = config.GetOrThrow("Oidc:ClientId");
    options.ClientSecret  = config.GetOrThrow("Oidc:ClientSecret");
    options.ResponseType  = "code";  // Authorization Code only
    options.UsePkce       = true;    // PKCE for code interception prevention
    options.SaveTokens    = false;   // do not store tokens in cookie
    options.GetClaimsFromUserInfoEndpoint = true;
    options.Scope.Add("openid");
    options.Scope.Add("profile");
    options.Scope.Add("email");

    options.TokenValidationParameters = new TokenValidationParameters
    {
        ValidateIssuer   = true,
        ValidIssuer      = config.GetOrThrow("Oidc:Authority"),
        ValidateAudience = true,
        ValidAudience    = config.GetOrThrow("Oidc:ClientId"),
        ValidateLifetime = true,
    };
});
```

---

## 14. SignalR Security

**Vulnerability:** SignalR Hub methods do not validate authorization by default. `[Authorize]` on the Hub class protects the connection handshake but not individual Hub methods if the token expires mid-session. Group membership (`Groups.AddToGroupAsync`) without server-side validation allows unauthorized room access.

**References:** CWE-284, CWE-862, OWASP A01:2021

### Mandatory Rules

- **Apply `[Authorize]` on both the Hub class and individual Hub methods** — class-level protects the connection; method-level handles post-connection authorization.
- **Validate group/room membership server-side** before calling `Groups.AddToGroupAsync()` — never trust client-supplied group names.
- **Validate Hub method arguments** — Hub methods receive user-supplied data; apply input validation.
- **Configure SignalR CORS explicitly** — never use `AllowAnyOrigin()` with SignalR hubs.
- **Use JWT bearer for WebSocket authentication** — cookies are auto-sent by browsers, but SignalR's fallback to query string token is a last resort and logs tokens in access logs.

```csharp
// ❌ INSECURE — No auth on Hub; any client can invoke hub methods
public class ChatHub : Hub
{
    public async Task JoinRoom(string roomId) =>
        await Groups.AddToGroupAsync(Context.ConnectionId, roomId); // unvalidated
    public async Task SendMessage(string room, string message) =>
        await Clients.Group(room).SendAsync("Message", message);
}

// ✅ SECURE — Authorized Hub with server-side group validation
[Authorize]
public class ChatHub : Hub
{
    private readonly IRoomService _rooms;
    public ChatHub(IRoomService rooms) => _rooms = rooms;

    [Authorize] // also on method — defensive
    public async Task JoinRoom(string roomId)
    {
        var userId = Context.UserIdentifier!;
        // Server-side: verify user is a member of this room
        if (!await _rooms.IsMemberAsync(userId, roomId))
            throw new HubException("Access denied to room.");
        await Groups.AddToGroupAsync(Context.ConnectionId, roomId);
    }

    [Authorize]
    public async Task SendMessage(string roomId, string message)
    {
        if (string.IsNullOrWhiteSpace(message) || message.Length > 2000)
            throw new HubException("Invalid message.");
        var userId = Context.UserIdentifier!;
        if (!await _rooms.IsMemberAsync(userId, roomId))
            throw new HubException("Access denied.");
        await Clients.Group(roomId).SendAsync("Message", new {
            UserId = userId, Text = message, SentAt = DateTime.UtcNow
        });
    }
}

// ✅ SECURE — JWT for SignalR (token from query string only as fallback)
builder.Services.AddAuthentication().AddJwtBearer(options =>
{
    options.Events = new JwtBearerEvents
    {
        OnMessageReceived = ctx =>
        {
            // SignalR sends token in query string for WS connections
            var token = ctx.Request.Query["access_token"].ToString();
            var path  = ctx.HttpContext.Request.Path;
            if (!string.IsNullOrEmpty(token) && path.StartsWithSegments("/hubs"))
                ctx.Token = token;
            return Task.CompletedTask;
        }
    };
});
```

---

## 15. Blazor Security

**Vulnerability:** Blazor Server leaks authorization state on reconnect if the auth state is not re-validated. Blazor WASM trusts client-side route guards that can be bypassed. `IJSRuntime.InvokeAsync<string>` with user-controlled arguments is susceptible to script injection. `NavigationManager.NavigateTo()` with user-supplied URLs enables open redirect.

**References:** CWE-284, CWE-79, CWE-601, OWASP A01:2021

### Mandatory Rules

- **Always re-validate authorization server-side** in Blazor Server — `[Authorize]` on Razor Components protects rendering, but underlying service calls must check permissions independently.
- **Never use `@((MarkupString)userContent)`** without sanitizing with a server-side sanitizer (HtmlSanitizer) — this is the Blazor equivalent of `innerHTML`.
- **Validate redirect targets in `NavigationManager.NavigateTo()`** — restrict to known internal paths.
- **Use `<AuthorizeView>`** components for UI hiding, but always enforce server-side authorization in `@code` blocks and service layers.
- **For Blazor WASM**: all authorization logic on the client is cosmetic — enforce every action server-side on the API.

```csharp
// ❌ INSECURE — Raw markup from user input (XSS)
@((MarkupString)userPost.Content)

// ❌ INSECURE — Open redirect via NavigateTo
NavigationManager.NavigateTo(Request.Query["returnUrl"]);

// ✅ SECURE — Sanitize before rendering as markup
@using HtmlSanitizer
@inject IHtmlSanitizer Sanitizer
@((MarkupString)Sanitizer.Sanitize(userPost.Content))

// ✅ SECURE — Open redirect prevention
private void SafeNavigate(string? returnUrl)
{
    // Only allow relative paths starting with /
    if (string.IsNullOrEmpty(returnUrl)
        || !Uri.IsWellFormedUriString(returnUrl, UriKind.Relative)
        || returnUrl.StartsWith("//")
        || returnUrl.Contains("://"))
    {
        returnUrl = "/";
    }
    NavigationManager.NavigateTo(returnUrl);
}

// ✅ SECURE — Blazor Server: re-validate auth in @code block, not only in component hierarchy
@attribute [Authorize]
@code {
    protected override async Task OnInitializedAsync()
    {
        // Re-validate: AuthorizeView may be stale after reconnect
        var authState = await AuthStateProvider.GetAuthenticationStateAsync();
        var user = authState.User;
        if (!user.Identity?.IsAuthenticated ?? true)
        {
            NavigationManager.NavigateTo("/login", forceLoad: true);
            return;
        }
        // Additional resource authorization
        var canAccess = await AuthzService.AuthorizeAsync(user, Resource, "OwnsResource");
        if (!canAccess.Succeeded)
            NavigationManager.NavigateTo("/forbidden", forceLoad: true);
    }
}
```

---

## 16. Minimal APIs Security Patterns

**Vulnerability:** Minimal APIs introduced in .NET 6 are concise but easy to misconfigure — missing `RequireAuthorization()`, missing input validation, inline error handling that exposes exceptions, and missing route parameter validation. Unlike controllers, Minimal APIs do not automatically apply filters registered via `options.Filters.Add()`.

**References:** CWE-284, CWE-20, CWE-209

### Mandatory Rules

- **Call `.RequireAuthorization()` on every Minimal API endpoint** or configure a fallback policy that requires authentication.
- **Use `TypedResults`** (not `Results`) for compile-time return type safety and OpenAPI schema generation.
- **Validate all route parameters and query strings** — `[AsParameters]` with a validated DTO + `ValidationFilter` or `FluentValidation`.
- **Use `app.MapGroup()` with shared middleware** to apply authorization, rate limiting, and validation to logical groups of endpoints.
- **Never expose raw exception details** — implement a global `Results.Problem()` fallback.

```csharp
// ❌ INSECURE — No auth, no validation, exposes exceptions
app.MapPost("/transfer", async (TransferRequest req, BankService svc) =>
{
    return await svc.Transfer(req.FromId, req.ToId, req.Amount); // no auth check
});

// ✅ SECURE — Group-level auth + validation filter
var apiGroup = app.MapGroup("/api")
    .RequireAuthorization()
    .RequireRateLimiting("api")
    .AddEndpointFilter<ValidationFilter<TransferRequest>>();

apiGroup.MapPost("/transfer", async (
    TransferRequest req,
    ClaimsPrincipal user,
    IAuthorizationService authz,
    BankService svc) =>
{
    // Verify source account is owned by the authenticated user
    var result = await authz.AuthorizeAsync(user, req.FromId, "OwnsAccount");
    if (!result.Succeeded) return TypedResults.Forbid();
    var transfer = await svc.Transfer(req.FromId, req.ToId, req.Amount);
    return TypedResults.Ok(transfer);
});

// ✅ SECURE — Global exception handler for Minimal APIs
app.UseExceptionHandler(errApp => errApp.Run(async ctx =>
{
    var ex = ctx.Features.Get<IExceptionHandlerFeature>()?.Error;
    var correlationId = Guid.NewGuid().ToString();
    var logger = ctx.RequestServices.GetRequiredService<ILogger<Program>>();
    logger.LogError(ex, "Unhandled exception. CorrelationId: {Id}", correlationId);
    ctx.Response.StatusCode = StatusCodes.Status500InternalServerError;
    await ctx.Response.WriteAsJsonAsync(new
    {
        Title   = "An unexpected error occurred.",
        Status  = 500,
        TraceId = correlationId,
        // Stack trace intentionally omitted
    });
}));
```

---

## 17. Swagger / OpenAPI Security in Production

**Vulnerability:** Leaving Swagger UI enabled in production exposes complete API documentation, request/response schemas, and an interactive playground to unauthenticated users — providing attackers with a detailed map of all endpoints and models.

**References:** CWE-200, CWE-497

### Mandatory Rules

- **Disable Swagger UI and OpenAPI JSON endpoints in production** — conditionally enable only in development/staging environments.
- **If Swagger must be available in production** (e.g., partner portals), require authentication for `/swagger` routes via `MapSwagger().RequireAuthorization()`.
- **Add security scheme definitions** (`SecurityDefinition`) to document authentication in Swagger — but restrict who can access the UI.
- **Remove sensitive fields** from Swagger schema — do not expose internal DTOs, database entity shapes, or stack trace response models.

```csharp
// ❌ INSECURE — Swagger enabled in all environments
app.UseSwagger();
app.UseSwaggerUI();
// Any unauthenticated user can see all API endpoints

// ✅ SECURE — Swagger only in development
if (app.Environment.IsDevelopment())
{
    app.UseSwagger();
    app.UseSwaggerUI(c =>
    {
        c.SwaggerEndpoint("/swagger/v1/swagger.json", "API v1");
        c.RoutePrefix = "swagger"; // not root
    });
}

// ✅ SECURE — If required in non-dev, protect with auth
if (!app.Environment.IsProduction())
{
    app.UseSwagger();
    app.MapSwagger().RequireAuthorization("SwaggerAccess");
    app.UseSwaggerUI();
}

// Security scheme definition (document JWT in Swagger)
builder.Services.AddSwaggerGen(options =>
{
    options.AddSecurityDefinition("Bearer", new OpenApiSecurityScheme
    {
        In = ParameterLocation.Header,
        Name = "Authorization",
        Type = SecuritySchemeType.Http,
        Scheme = "bearer",
        BearerFormat = "JWT",
    });
    options.AddSecurityRequirement(new OpenApiSecurityRequirement
    {
        {
            new OpenApiSecurityScheme
            {
                Reference = new OpenApiReference
                    { Type = ReferenceType.SecurityScheme, Id = "Bearer" }
            },
            []
        }
    });
});
```

---

## CVE Reference Table

| CVE | Severity | Component | Description | Fixed In |
|-----|----------|-----------|-------------|----------|
| CVE-2024-35264 | Critical (9.8) | ASP.NET Core (.NET 8) | Remote code execution via HTTP/3 request processing — use-after-free in Kestrel HTTP/3 stack | .NET 8.0.7 |
| CVE-2024-38095 | High (7.5) | ASP.NET Core (.NET 8/9) | Denial of service via malformed HTTP/2 HPACK encoded headers in SignalR connections | .NET 8.0.7 |
| CVE-2024-38168 | High (7.5) | ASP.NET Core (.NET 8) | Denial of service via malformed HTTP/2 CONTINUATION frames | .NET 8.0.8 |
| CVE-2024-43483 | High (7.5) | System.Text.Json / .NET | StackOverflow denial of service when deserializing deeply nested JSON (unbounded depth) | .NET 8.0.10 |
| CVE-2024-43485 | High (7.5) | System.Text.Json / .NET | StackOverflow DoS via deeply nested JSON in extension data handling | .NET 8.0.10 |
| CVE-2024-21319 | Medium (6.3) | Microsoft.Identity.Web | Server-side request forgery (SSRF) via metadata endpoint URL configuration | 2.15.3 |
| CVE-2023-35391 | High (7.5) | ASP.NET Core SignalR | Connection hub denial of service via specially crafted WebSocket requests | .NET 7.0.9 |
| CVE-2023-33170 | High (8.1) | ASP.NET Core Identity | Security feature bypass — timing attack in `PasswordHasher` comparison allowing enumeration | .NET 7.0.9 |
| CVE-2022-34716 | Medium (5.9) | ASP.NET Core / .NET 6 | Information disclosure: TLS private key exposed via parsing of malformed PEM blocks | .NET 6.0.8 |
| CVE-2024-30105 | High (7.5) | System.Text.Json (.NET 8) | StackOverflow DoS via `JsonElement.WriteTo()` on deeply nested JSON arrays | .NET 8.0.7 |

---

## Security Checklist

### Middleware Pipeline
- [ ] Middleware registered in correct order: HSTS → HTTPS redirect → static files → routing → CORS → authentication → authorization → antiforgery → endpoints
- [ ] `UseDeveloperExceptionPage()` only in development; `UseExceptionHandler()` in production
- [ ] `UseHsts()` in production with `IncludeSubDomains: true`, `Preload: true`, `MaxAge` ≥ 1 year
- [ ] `UseHttpsRedirection()` applied in all non-development environments

### Authentication & Identity
- [ ] Password policy: min 12 chars, uppercase, lowercase, digit, non-alphanumeric
- [ ] Lockout: `MaxFailedAccessAttempts: 5`, `DefaultLockoutTimeSpan: 15 min`, `AllowedForNewUsers: true`
- [ ] `RequireConfirmedEmail: true` before login
- [ ] Cookie: `HttpOnly: true`, `Secure: Always`, `SameSite: Strict`, absolute expiry set
- [ ] Session ID regenerated after privilege change (re-sign-in)

### Authorization
- [ ] All endpoints protected by default (fallback policy or explicit `RequireAuthorization()`)
- [ ] Named authorization policies in `AddAuthorizationBuilder()` — no inline role checks
- [ ] Resource-based authorization (`IAuthorizationService.AuthorizeAsync`) for user-owned data
- [ ] Minimal API endpoints each have `.RequireAuthorization()` or covered by group policy

### Data Protection API
- [ ] Key ring persisted to durable storage (Azure Blob, Redis, S3) — not in-memory
- [ ] Key ring encrypted at rest (Azure Key Vault, certificate, DPAPI)
- [ ] `SetApplicationName()` set consistently across all instances
- [ ] Key lifetime and rotation policy configured

### CSRF & Anti-Forgery
- [ ] `AutoValidateAntiforgeryTokenAttribute` applied globally on MVC controllers
- [ ] Razor Pages: anti-forgery enabled (default) and not disabled
- [ ] Minimal API form endpoints: `UseAntiforgery()` middleware + `ValidateAntiforgery()`
- [ ] Auth/session cookies use `SameSite=Strict`

### Model Binding & Input Validation
- [ ] All controller actions use DTOs/ViewModels — not entity classes
- [ ] No `TryUpdateModelAsync` without explicit field allowlist on database entities
- [ ] Input validated via Data Annotations, FluentValidation, or explicit checks
- [ ] Maximum sizes enforced on string inputs and request bodies

### Entity Framework Core
- [ ] `FromSqlInterpolated()` used instead of `FromSqlRaw()` for parameterized queries
- [ ] No `FromSqlRaw()` or `ExecuteSqlRaw()` with string concatenation/interpolation
- [ ] API responses project to DTO types — no full entity graphs returned
- [ ] `logging` not enabled in production (avoids logging parameter values)

### File Uploads
- [ ] `IFormFile.FileName` never used as storage filename — UUID used instead
- [ ] Magic bytes validated (not just `ContentType` header)
- [ ] Maximum upload size enforced via `RequestSizeLimitAttribute` + Kestrel config
- [ ] Files stored outside `wwwroot` — served via controller with `Content-Disposition: attachment`

### Security Headers
- [ ] `X-Content-Type-Options: nosniff` on all responses
- [ ] `X-Frame-Options: DENY` (or SAMEORIGIN where embedding is needed)
- [ ] `Content-Security-Policy` header configured (no `unsafe-eval` unless required)
- [ ] `Server` and `X-Powered-By` headers removed
- [ ] `Referrer-Policy: strict-origin-when-cross-origin` set

### Rate Limiting
- [ ] `AddRateLimiter()` registered and `UseRateLimiter()` applied before `UseAuthorization()`
- [ ] Auth endpoints limited to 5 requests/minute per IP
- [ ] API endpoints have sliding window or token bucket limits
- [ ] `RejectionStatusCode = 429` with `Retry-After` header on rejection

### CORS
- [ ] Named policy used — no default/unnamed policy
- [ ] `AllowAnyOrigin().AllowCredentials()` never used
- [ ] Allowed origins read from configuration — not hardcoded
- [ ] `UseCors()` placed before endpoint middleware

### OIDC / OAuth2
- [ ] `UsePkce = true` with Authorization Code flow
- [ ] `state` and `nonce` validated (enabled by default — not disabled)
- [ ] `Authority` pinned from configuration — no dynamic issuer
- [ ] `iss` and `aud` claims validated in `TokenValidationParameters`
- [ ] Tokens not logged in any middleware or event handler

### SignalR
- [ ] `[Authorize]` on Hub class AND individual Hub methods
- [ ] Group membership validated server-side before `Groups.AddToGroupAsync()`
- [ ] Hub method arguments validated
- [ ] CORS for SignalR hub endpoints uses explicit origin allowlist

### Blazor
- [ ] No `@((MarkupString)userContent)` without server-side HTML sanitization
- [ ] `NavigationManager.NavigateTo()` validates redirect targets (relative paths only)
- [ ] Blazor Server: authorization re-validated in `@code` blocks, not only in component hierarchy
- [ ] Blazor WASM: all authorization enforced server-side on API — client guards are UI-only

### Swagger / OpenAPI
- [ ] Swagger UI disabled in production
- [ ] If enabled in staging, protected with `RequireAuthorization("SwaggerAccess")`
- [ ] No internal entity types or sensitive response models in Swagger schema

---

## Tooling

| Tool | Purpose | Command |
|------|---------|---------|
| [dotnet-outdated](https://github.com/dotnet-outdated/dotnet-outdated) | Check for outdated NuGet packages | `dotnet outdated` |
| [dotnet audit](https://learn.microsoft.com/en-us/dotnet/core/tools/dotnet-package-search) | NuGet vulnerability scanning | `dotnet list package --vulnerable --include-transitive` |
| [Snyk for .NET](https://snyk.io/docs/snyk-for-.net/) | Advanced dependency + code scanning | `snyk test --file=*.csproj` |
| [Microsoft Security Code Analysis](https://docs.microsoft.com/en-us/azure/security/develop/security-code-analysis-overview) | Roslyn analyzers for security anti-patterns | Add `Microsoft.CodeAnalysis.NetAnalyzers` NuGet |
| [Roslynator](https://github.com/dotnet/roslynator) | Code quality + security Roslyn rules | Add `Roslynator.Analyzers` NuGet |
| [PVS-Studio](https://pvs-studio.com/en/pvs-studio/) | Static analysis with security checks | `pvs-studio-dotnet --target *.sln` |
| [OWASP ZAP](https://owasp.org/www-project-zap/) | Dynamic application security testing (DAST) | `zap-cli quick-scan http://localhost:5000` |
| [dotnet-retire](https://github.com/RetireNet/dotnet-retire) | Detect known-vulnerable NuGet packages | `dotnet retire` |
| [HtmlSanitizer](https://github.com/mganss/HtmlSanitizer) | Server-side HTML sanitization for Blazor | `dotnet add package HtmlSanitizer` |
| [NetEscapades.AspNetCore.SecurityHeaders](https://github.com/andrewlock/NetEscapades.AspNetCore.SecurityHeaders) | Security header middleware | `dotnet add package NetEscapades.AspNetCore.SecurityHeaders` |
| [BenchmarkDotNet](https://github.com/dotnet/BenchmarkDotNet) | Timing attack detection (constant-time comparison benchmarks) | `dotnet add package BenchmarkDotNet` |
