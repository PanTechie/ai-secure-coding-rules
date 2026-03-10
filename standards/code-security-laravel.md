# 🔴 Laravel Security Rules

> **Standard:** Secure coding rules for Laravel applications (v9/v10/v11), covering Eloquent mass assignment, SQL injection via raw query methods, Blade XSS, CSRF, authentication hardening, authorization policies, file uploads, secrets management, queue security, and Laravel Sanctum/Passport.
> **Sources:** Laravel Official Security Documentation, OWASP PHP Security Cheat Sheet, CVE Database/NVD, OWASP Top 10:2025, Snyk PHP Security Advisories, Enlightn Security Advisories, Roave Security Advisories
> **Version:** 1.0.0
> **Last updated:** March 2026
> **Scope:** Laravel framework patterns — Eloquent, Blade, middleware pipeline, Auth/Sanctum/Passport, Gates/Policies, Queues, Storage, HTTP Client, and Artisan. Core PHP language rules are in `code-security-php.md`.

---

## General Instructions

Apply these rules to all Laravel code generation, review, and refactoring tasks. Laravel provides many safe defaults — Eloquent parameterizes queries, Blade auto-escapes output, and `@csrf` protects forms — but each can be bypassed with unsafe alternatives: `DB::select()` with string interpolation, `{!! !!}` syntax, or excluding routes from `VerifyCsrfToken`. Always verify that safe APIs are used and that unsafe escape hatches are flagged.

---

## 1. SQL Injection — Raw Query Methods

**Vulnerability:** Laravel's Eloquent ORM generates parameterized SQL automatically, but `whereRaw()`, `selectRaw()`, `orderByRaw()`, `groupByRaw()`, `havingRaw()`, and `DB::statement()` / `DB::select()` accept raw SQL strings. Interpolating user input into these methods produces SQL injection — even through `request()` values that appear innocuous.

**References:** CWE-89, OWASP A03:2021

### Mandatory Rules

- **Use Eloquent query builder methods** (`where()`, `select()`, `orderBy()`) wherever possible — they are always parameterized.
- **When using `whereRaw()`, `selectRaw()`, `havingRaw()`** always pass user values as a bindings array — the second argument — never interpolate them into the SQL string.
- **Never use `DB::statement()`, `DB::select()`, `DB::insert()`, or `DB::update()` with string concatenation** of user-controlled values.
- **Validate sort column names against an allowlist** before passing to `orderBy()` — even though Eloquent's `orderBy()` is parameterized, dynamic column names can bypass quoting.
- **Use `DB::getPdo()->quote()`** only as a last resort — prefer bindings arrays.

```php
// ❌ INSECURE — String interpolation in whereRaw
$users = DB::table('users')
    ->whereRaw("name = '{$request->name}'") // SQL injection
    ->get();

// ❌ INSECURE — User-controlled column in orderByRaw
$users = User::orderByRaw($request->sort)->get(); // SQL injection

// ❌ INSECURE — DB::select with concatenation
$results = DB::select("SELECT * FROM users WHERE email = '" . $request->email . "'");

// ✅ SECURE — Eloquent (always parameterized)
$users = User::where('name', $request->name)->get();

// ✅ SECURE — whereRaw with bindings array
$users = DB::table('users')
    ->whereRaw('name = ? AND status = ?', [$request->name, $request->status])
    ->get();

// ✅ SECURE — Allowlist for dynamic sort columns
$allowed = ['name', 'created_at', 'email'];
$sort = in_array($request->sort, $allowed, true) ? $request->sort : 'created_at';
$users = User::orderBy($sort, 'asc')->get();

// ✅ SECURE — DB::select with bindings
$results = DB::select('SELECT * FROM users WHERE email = ?', [$request->email]);
```

---

## 2. Mass Assignment — $fillable, $guarded, forceFill

**Vulnerability:** `Model::create(request()->all())` or `$model->fill(request()->all())` copies every request key to the model if `$guarded = []` is set or if `$fillable` does not explicitly exclude sensitive fields (`is_admin`, `role`, `email_verified_at`, `stripe_id`). `forceFill()` bypasses both `$fillable` and `$guarded` entirely — it is equivalent to having no protection.

**References:** CWE-915, OWASP A04:2021, CVE-2021-43617

### Mandatory Rules

- **Always define `$fillable`** with an explicit allowlist of safe fields — never rely on `$guarded = []` in production models.
- **Never use `Model::create(request()->all())`** or `$model->fill($request->all())` without first validating and selecting only expected fields.
- **Never use `forceFill()`** with user-supplied data — it bypasses all mass assignment protection.
- **Use `$request->validated()`** (from FormRequest) or `$request->only(['field1', 'field2'])` as the input to `create()`/`fill()`.
- **Keep sensitive fields out of `$fillable`**: `is_admin`, `role`, `email_verified_at`, `remember_token`, `password`, `stripe_id`, `subscription_status`.

```php
// ❌ INSECURE — $guarded = [] allows all fields including is_admin
class User extends Model {
    protected $guarded = []; // no protection
}
User::create($request->all()); // attacker sends { "is_admin": true }

// ❌ INSECURE — forceFill bypasses fillable/guarded
$user->forceFill($request->all())->save();

// ✅ SECURE — Explicit $fillable allowlist
class User extends Model {
    protected $fillable = ['name', 'email']; // is_admin intentionally omitted
}

// ✅ SECURE — Use validated() from FormRequest
class UpdateProfileRequest extends FormRequest {
    public function rules(): array {
        return [
            'name'  => ['required', 'string', 'max:100'],
            'email' => ['required', 'email', 'unique:users,email,' . $this->user()->id],
            // is_admin NOT in rules — cannot be mass-assigned even if posted
        ];
    }
}

public function update(UpdateProfileRequest $request): JsonResponse {
    $request->user()->update($request->validated());
    // $request->validated() only contains fields defined in rules()
    return response()->json(['message' => 'Updated']);
}
```

---

## 3. Blade XSS — {{ }} vs {!! !!}

**Vulnerability:** Blade's `{{ $var }}` auto-escapes output using `htmlspecialchars()`. The `{!! $var !!}` syntax outputs raw, unescaped HTML — enabling reflected and stored XSS when the variable contains user-controlled content. Developers often use `{!! !!}` for rich text without sanitizing it first.

**References:** CWE-79, OWASP A03:2021

### Mandatory Rules

- **Always use `{{ $var }}`** for user-controlled output — Blade auto-escapes to prevent XSS.
- **Never use `{!! $var !!}` with user-supplied content** unless the content has been sanitized with a server-side allowlist sanitizer.
- **Use the `HTMLPurifier` package** (or `mews/purifier`) to sanitize rich HTML input before storing or rendering with `{!! !!}`.
- **Never use `@php echo $var; @endphp`** with user content — it also outputs raw HTML.
- **Sanitize rich text at storage time** (when saving to DB), not only at render time — defense in depth.

```php
// ❌ INSECURE — Raw output of user content
{!! $post->content !!}  {{-- XSS if content contains <script> --}}
{!! $user->bio !!}

// ❌ INSECURE — @php echo with user content
@php echo $comment->text; @endphp

// ✅ SECURE — Auto-escaped Blade output (safe for plain text)
{{ $post->title }}
{{ $user->email }}

// ✅ SECURE — Sanitize rich HTML with HTMLPurifier before {!! !!}
// config/purifier.php defines allowlist: <p>, <strong>, <em>, <a href>, <ul>, <li>
{!! clean($post->content) !!}  {{-- mews/purifier: clean() runs HTMLPurifier --}}

// ✅ SECURE — Sanitize at write time in a service
use Mews\Purifier\Facades\Purifier;

public function store(StorePostRequest $request): RedirectResponse {
    Post::create([
        'title'   => $request->validated('title'),   // plain text — no sanitizer needed
        'content' => Purifier::clean($request->validated('content')), // rich HTML sanitized
        'user_id' => $request->user()->id,
    ]);
    return redirect()->route('posts.index');
}
```

---

## 4. CSRF Protection

**Vulnerability:** Laravel's `VerifyCsrfToken` middleware protects POST/PUT/PATCH/DELETE routes by default, but developers sometimes add routes to `$except` or disable the middleware entirely for API routes. SPA and mobile API routes should use Sanctum's cookie-based CSRF protection, not anonymous API endpoints.

**References:** CWE-352, OWASP A01:2021

### Mandatory Rules

- **Include `@csrf` in every HTML form** — Blade forms without it fail CSRF validation (but check the `$except` list isn't bypassing this).
- **Never add sensitive state-changing routes to `VerifyCsrfToken::$except`** — if a route must be excluded for webhooks, verify the request via a webhook signature instead.
- **For SPAs using Sanctum**, call `GET /sanctum/csrf-cookie` before every state-changing request and send the `X-XSRF-TOKEN` header.
- **For pure REST APIs using tokens** (Bearer Auth), exclude API routes from CSRF but require `Authorization: Bearer` header — browsers cannot set this header cross-site.
- **Configure session cookies with `SameSite=strict`** in `config/session.php` for cookie-authenticated apps.

```php
// ❌ INSECURE — Sensitive route excluded from CSRF
class VerifyCsrfToken extends Middleware {
    protected $except = [
        'payment/process',  // state-changing — should NOT be excluded
        'admin/*',
    ];
}

// ❌ INSECURE — HTML form missing @csrf
<form method="POST" action="/transfer">
    <input name="amount" value="1000">
    <button>Submit</button>
</form>

// ✅ SECURE — @csrf in Blade form
<form method="POST" action="{{ route('transfer.store') }}">
    @csrf
    <input name="amount" value="1000">
    <button>Submit</button>
</form>

// ✅ SECURE — Webhook excluded with signature verification
class VerifyCsrfToken extends Middleware {
    protected $except = ['webhooks/stripe']; // verified via Stripe-Signature header
}

// routes/web.php — webhook with signature verification
Route::post('/webhooks/stripe', function (Request $request) {
    $event = Webhook::constructEvent(
        $request->getContent(),
        $request->header('Stripe-Signature'),
        config('services.stripe.webhook_secret')
    );
    // process $event
});

// config/session.php
'same_site' => 'strict', // prevents cross-site cookie submission
```

---

## 5. Authentication Hardening

**Vulnerability:** Default Laravel authentication (Breeze/Fortify) does not enforce account lockout after brute-force attempts, does not regenerate the session ID after login (session fixation), and may allow weak passwords without additional configuration.

**References:** CWE-307, CWE-521, CWE-384, OWASP A07:2021

### Mandatory Rules

- **Enable login throttling** — Laravel Fortify's `RateLimiting::for('login')` limits attempts per IP/email; ensure it is configured.
- **Always call `$request->session()->regenerate()`** after a successful login to prevent session fixation.
- **Hash passwords with `Hash::make()`** (bcrypt by default, or Argon2id via `config/hashing.php`) — never use `md5()`, `sha1()`, or `sha256()` for passwords.
- **Never compare passwords with `==`** — always use `Hash::check($plain, $hashed)`.
- **Set `APP_DEBUG=false` in production** — debug mode (CVE-2021-3129) enables RCE via Ignition's file-read gadgets in older versions.
- **Verify email before granting access** to sensitive features — use `EnsureEmailIsVerified` middleware.

```php
// ❌ INSECURE — No session regeneration after login (session fixation)
public function login(Request $request): RedirectResponse {
    if (Auth::attempt($request->only('email', 'password'))) {
        // session ID unchanged — fixation possible
        return redirect()->intended('/dashboard');
    }
    return back()->withErrors(['email' => 'Invalid credentials']);
}

// ❌ INSECURE — MD5 password comparison
if (md5($request->password) === $user->password_hash) { // easily reversed

// ✅ SECURE — Session regeneration + throttling + bcrypt
public function login(Request $request): RedirectResponse {
    $request->validate([
        'email'    => ['required', 'email'],
        'password' => ['required', 'string'],
    ]);

    if (Auth::attempt($request->only('email', 'password'), $request->boolean('remember'))) {
        $request->session()->regenerate(); // prevent session fixation
        return redirect()->intended('/dashboard');
    }
    return back()->withErrors(['email' => __('auth.failed')])->onlyInput('email');
}

// config/fortify.php — rate limiting (Fortify)
// RateLimiting::for('login', function (Request $request) {
//     return Limit::perMinute(5)->by($request->email.$request->ip());
// });

// config/hashing.php — Argon2id for higher security
'driver' => 'argon2id',
'argon' => ['memory' => 65536, 'threads' => 1, 'time' => 4],
```

---

## 6. Authorization — Gates, Policies & Middleware

**Vulnerability:** Relying solely on route-level `auth` middleware without resource-level authorization allows authenticated users to access other users' data (IDOR). Using `@can` in Blade for UI hiding without enforcing the same check server-side in the controller is also dangerous.

**References:** CWE-284, CWE-285, OWASP A01:2021

### Mandatory Rules

- **Define Policies** for every Eloquent model that is accessible via HTTP — never perform authorization only in Blade or only in the route definition.
- **Call `$this->authorize()`** in every controller method that accesses a specific resource instance.
- **Use `Gate::authorize()`** or `$this->authorize()` — not just `Gate::check()` (which returns a bool and does not throw on failure).
- **Never derive authorization from request body parameters** (e.g., `$request->user_id`) — always read the authenticated user from `Auth::user()` or `$request->user()`.
- **Scope Eloquent queries to the authenticated user** where applicable (`where('user_id', auth()->id())`) to prevent IDOR at the database level.

```php
// ❌ INSECURE — IDOR: any authenticated user can delete any post
public function destroy(Post $post): RedirectResponse {
    $post->delete();
    return redirect()->route('posts.index');
}

// ❌ INSECURE — Authorization only in Blade, not controller
// Blade: @can('update', $post) ... @endcan — UI only, controller unprotected

// ✅ SECURE — Policy-based authorization in controller
// app/Policies/PostPolicy.php
class PostPolicy {
    public function update(User $user, Post $post): bool {
        return $user->id === $post->user_id;
    }
    public function delete(User $user, Post $post): bool {
        return $user->id === $post->user_id || $user->hasRole('admin');
    }
}

// app/Http/Controllers/PostController.php
public function update(UpdatePostRequest $request, Post $post): RedirectResponse {
    $this->authorize('update', $post); // throws 403 if user doesn't own post
    $post->update($request->validated());
    return redirect()->route('posts.show', $post);
}

public function destroy(Post $post): RedirectResponse {
    $this->authorize('delete', $post);
    $post->delete();
    return redirect()->route('posts.index');
}

// ✅ SECURE — Scope query to current user (IDOR prevention at DB level)
public function index(Request $request): JsonResponse {
    $posts = Post::where('user_id', $request->user()->id)->paginate(20);
    return response()->json($posts);
}
```

---

## 7. File Upload Security

**Vulnerability:** Laravel's `store()` method generates a safe random filename, but `storeAs()` with `$request->file()->getClientOriginalName()` preserves the user-supplied filename — enabling path traversal and overwriting existing files. MIME type validation using only `mimes:` rule checks the extension, not the actual file content.

**References:** CWE-434, CWE-22, OWASP A04:2021

### Mandatory Rules

- **Always use `store()` (random UUID filename)** — never use `storeAs($path, $request->file()->getClientOriginalName())`.
- **Validate file content using `mimetypes:` rule** (which uses `finfo` for magic-byte detection) rather than `mimes:` (which trusts the extension).
- **Use the `local` disk (not `public`)** for sensitive uploads — serve through a signed URL or controller endpoint.
- **Set maximum file size** in both the validation rule and `php.ini`/`config/filesystems.php`.
- **Never serve uploaded files with `Content-Type` derived from the uploaded file's MIME type** — force `application/octet-stream` or `Content-Disposition: attachment` for non-image types.
- **Never store uploads at paths derived from user input** — use fixed directories with random filenames.

```php
// ❌ INSECURE — Original filename preserved (path traversal + overwrite)
$path = $request->file('avatar')->storeAs(
    'avatars',
    $request->file('avatar')->getClientOriginalName() // "../../config/app.php"
);

// ❌ INSECURE — mimes: checks extension only (attacker renames .php to .jpg)
$request->validate(['avatar' => 'mimes:jpeg,png|max:2048']);

// ✅ SECURE — store() with random filename + magic-byte MIME check
$request->validate([
    'avatar' => [
        'required',
        'file',
        'mimetypes:image/jpeg,image/png,image/webp', // finfo magic bytes
        'max:5120', // 5 MB
    ],
]);

$path = $request->file('avatar')->store('avatars', 'local');
// stored as: avatars/a1b2c3d4-random-uuid.jpg — original name discarded

// ✅ SECURE — Serve via signed URL (not public disk)
return Storage::disk('local')->temporaryUrl($path, now()->addMinutes(15));

// ✅ SECURE — Controller download with Content-Disposition: attachment
public function download(string $filename, Request $request): StreamedResponse {
    // Validate ownership
    $upload = Upload::where('filename', $filename)
        ->where('user_id', $request->user()->id)
        ->firstOrFail();

    return Storage::disk('local')->download(
        $upload->path,
        $upload->original_name,
        ['Content-Disposition' => 'attachment']
    );
}
```

---

## 8. Secrets & Environment Configuration

**Vulnerability:** Committing `.env` files, setting `APP_DEBUG=true` in production (CVE-2021-3129 enables RCE), using `env()` calls directly in code outside of `config/` files (breaks config caching), and hardcoding secrets in config files are all common Laravel security failures.

**References:** CWE-312, CWE-798, CVE-2021-3129, CVE-2018-15133

### Mandatory Rules

- **Set `APP_DEBUG=false` in production** — `APP_DEBUG=true` with Ignition ≤ 2.5.1 allows unauthenticated RCE via file-write gadgets (CVE-2021-3129).
- **Generate a strong `APP_KEY`** (`php artisan key:generate`) — the key is used to sign and encrypt cookies; a leaked or weak key enables cookie forgery and RCE (CVE-2018-15133).
- **Never call `env()` outside `config/` files** — use `config('app.my_setting')` everywhere else; `env()` always returns `null` after `php artisan config:cache`.
- **Add `.env` to `.gitignore`** and never commit credentials — use `.env.example` with placeholder values.
- **Use Laravel Vault integration or AWS Secrets Manager** for production secrets rather than `.env` files on disk.
- **Rotate `APP_KEY` when compromised** using `php artisan key:generate --force` — invalidates all existing encrypted cookies and sessions.

```php
// ❌ INSECURE — APP_DEBUG=true in production (RCE via CVE-2021-3129)
// .env
APP_ENV=production
APP_DEBUG=true  // exposes stack traces, environment, secrets in error pages

// ❌ INSECURE — env() called outside config/ (breaks config caching)
// In a service provider:
$secret = env('PAYMENT_SECRET'); // returns null after config:cache

// ❌ INSECURE — Hardcoded secret in config
// config/services.php
'stripe' => ['secret' => 'sk_live_hardcoded_secret_here'],

// ✅ SECURE — .env for production
APP_ENV=production
APP_DEBUG=false
APP_KEY=base64:STRONG_RANDOM_64_CHAR_KEY_HERE

// ✅ SECURE — config/ accesses env(), services access config()
// config/services.php
'stripe' => [
    'secret' => env('STRIPE_SECRET'),
    'webhook_secret' => env('STRIPE_WEBHOOK_SECRET'),
],

// In service class — use config(), not env()
$secret = config('services.stripe.secret');

// ✅ SECURE — .gitignore
.env
.env.*.local
storage/app/private/
```

---

## 9. Open Redirect & URL Validation

**Vulnerability:** `redirect()->to($request->input('redirect'))` or `redirect()->away($url)` with unvalidated user-supplied URLs enables open redirects — used for phishing and OAuth token theft. Laravel's `url()->isValidUrl()` only checks syntax, not safety.

**References:** CWE-601, OWASP A01:2021, CVE-2024-52301

### Mandatory Rules

- **Never pass user-supplied URLs directly to `redirect()`** — validate against an allowlist of trusted domains.
- **Use `redirect()->intended('/default')`** instead of `redirect($request->get('redirect'))` for post-login flows — Laravel tracks the intended URL in the session, not in the query string.
- **Validate that redirect URLs are relative paths** (start with `/`, not `//` or `http://`) when allowing post-action redirects.
- **Never use `redirect()->away($url)`** with user-controlled input — it redirects to any external URL.

```php
// ❌ INSECURE — Open redirect via query parameter
return redirect($request->input('redirect')); // attacker: ?redirect=https://evil.com

// ❌ INSECURE — redirect()->away() with user input
return redirect()->away($request->input('callback_url'));

// ✅ SECURE — Use intended() for post-login redirect (URL stored in session)
if (Auth::attempt($credentials)) {
    $request->session()->regenerate();
    return redirect()->intended('/dashboard'); // from session, not query string
}

// ✅ SECURE — Allowlist for trusted redirect domains
function safeRedirect(string $url, string $default = '/'): RedirectResponse {
    $allowed = ['app.example.com', 'admin.example.com'];
    $host = parse_url($url, PHP_URL_HOST);

    // Allow only relative URLs or approved hosts
    if ($host === null && str_starts_with($url, '/') && !str_starts_with($url, '//')) {
        return redirect($url);
    }
    if ($host !== null && in_array($host, $allowed, true)) {
        return redirect($url);
    }
    return redirect($default);
}

// ✅ SECURE — Validate relative path only
$returnTo = $request->input('return_to', '/');
if (!filter_var($returnTo, FILTER_VALIDATE_URL)
    && str_starts_with($returnTo, '/')
    && !str_starts_with($returnTo, '//')) {
    return redirect($returnTo);
}
return redirect('/');
```

---

## 10. HTTP Client — SSRF

**Vulnerability:** Laravel's `Http::get($url)` with user-controlled URLs enables Server-Side Request Forgery (SSRF) — attackers reach internal services (`http://169.254.169.254/`), private network hosts, or the `file://` scheme. Laravel's HTTP Client does not validate URLs against private IP ranges by default.

**References:** CWE-918, OWASP A10:2021

### Mandatory Rules

- **Never pass user-supplied URLs directly to `Http::get()`** or `Http::post()`.
- **Validate URLs against an allowlist of permitted hostnames** before making outbound requests.
- **Block private IP ranges and metadata endpoints** — resolve the URL and reject RFC 1918, RFC 5735, loopback, and link-local addresses.
- **Set explicit timeouts** on all `Http` calls (`Http::timeout(5)->get($url)`) — no timeout means a slow target can exhaust workers.
- **Disable redirects** or validate redirect destinations with the same allowlist (`Http::withOptions(['allow_redirects' => false])`).

```php
// ❌ INSECURE — SSRF: user controls URL
public function preview(Request $request): JsonResponse {
    $response = Http::get($request->input('url')); // attacker: http://169.254.169.254/
    return response()->json($response->json());
}

// ✅ SECURE — Hostname allowlist + private IP blocking
function isSafeUrl(string $url): bool {
    $allowed = ['api.partner.com', 'webhooks.trusted.com'];
    $parsed = parse_url($url);
    if (!$parsed || !isset($parsed['host'])) return false;
    if (!in_array(strtolower($parsed['scheme'] ?? ''), ['https'], true)) return false;
    if (!in_array($parsed['host'], $allowed, true)) return false;

    // Resolve and check for private IPs
    $ips = gethostbynamel($parsed['host']) ?: [];
    foreach ($ips as $ip) {
        if (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE) === false) {
            return false; // private/reserved range
        }
    }
    return true;
}

public function testWebhook(Request $request): JsonResponse {
    $url = $request->validated('callback_url');
    if (!isSafeUrl($url)) {
        abort(400, 'URL not allowed.');
    }
    $response = Http::timeout(5)
        ->withOptions(['allow_redirects' => false])
        ->get($url);
    return response()->json(['status' => $response->status()]);
}
```

---

## 11. Command Injection & Artisan Security

**Vulnerability:** Using `exec()`, `system()`, `shell_exec()`, or `passthru()` with user-controlled input inside Laravel controllers or services enables command injection. `Artisan::call()` with dynamically constructed command strings can also be exploited if argument values are not validated.

**References:** CWE-78, OWASP A03:2021

### Mandatory Rules

- **Never use `exec()`, `system()`, `shell_exec()`, `passthru()`, or backticks** with user-controlled input — use Laravel's `Process` facade (Laravel 10+) or Symfony's `Process` with argument arrays.
- **Use `Process::run(['cmd', 'arg1', 'arg2'])`** with an array of arguments — never construct a shell command string via concatenation.
- **Validate and allowlist any values** passed to `Artisan::call()` — do not derive command or argument values from user input.
- **Escape arguments with `escapeshellarg()`** only as a last resort when refactoring legacy code — prefer argument arrays.

```php
// ❌ INSECURE — Command injection via user-controlled input
$filename = $request->input('file');
exec("convert $filename output.pdf"); // attacker: "x; rm -rf /"

// ❌ INSECURE — shell_exec with user input
$result = shell_exec('ffmpeg -i ' . $request->input('video_url') . ' output.mp4');

// ✅ SECURE — Laravel Process facade with argument array (Laravel 10+)
use Illuminate\Support\Facades\Process;

$safeFilename = basename($request->validated('filename')); // strip path components
$result = Process::run(['convert', '/uploads/' . $safeFilename, 'output.pdf']);
if ($result->failed()) {
    Log::error('Conversion failed', ['output' => $result->errorOutput()]);
    abort(500, 'Processing failed.');
}

// ✅ SECURE — Symfony Process for older Laravel (argument array, no shell)
use Symfony\Component\Process\Process;

$process = new Process(['ffmpeg', '-i', $validatedPath, '/tmp/output.mp4']);
$process->setTimeout(60);
$process->run();
```

---

## 12. Queue & Job Security

**Vulnerability:** Laravel queue jobs serialize their payload using PHP serialization. Storing sensitive data (passwords, API keys, full user objects) in job payloads exposes them in queue backends (Redis, database). Additionally, jobs that accept user-controlled class names or method names via dynamic dispatch can enable deserialization attacks.

**References:** CWE-502, CWE-312, OWASP A02:2021

### Mandatory Rules

- **Never store plaintext secrets, passwords, or tokens in job payloads** — store only identifiers (user ID, order ID) and re-fetch from database in `handle()`.
- **Use `SerializesModels`** trait — it stores only the model's primary key and re-hydrates via a fresh query in the worker, avoiding stale data and large payloads.
- **Never dispatch jobs where the class name or method is user-controlled** — this enables deserialization-based RCE via gadget chains.
- **Enable queue payload encryption** (`'encrypt' => true` in `config/queue.php`) for sensitive queues — encrypts job payloads at rest.
- **Validate job input data** — jobs receive serialized data from an external queue; always validate before using.

```php
// ❌ INSECURE — Sensitive data in job payload
class SendWelcomeEmail implements ShouldQueue {
    public function __construct(
        public string $email,
        public string $password,  // plaintext password in queue payload!
        public string $apiKey,    // API key in Redis/DB queue
    ) {}
}

// ❌ INSECURE — Full model object without SerializesModels (large, stale, exposes all fields)
class ProcessOrder implements ShouldQueue {
    public function __construct(public Order $order) {} // full serialized model
}

// ✅ SECURE — Store only IDs, re-fetch in handle()
class SendWelcomeEmail implements ShouldQueue {
    use Dispatchable, InteractsWithQueue, Queueable, SerializesModels;

    public function __construct(public int $userId) {}
    // SerializesModels: if type-hinted as User model, stores only ID

    public function handle(UserRepository $repo, Mailer $mailer): void {
        $user = $repo->findOrFail($this->userId);
        // Re-fetch from DB — fresh data, no serialized secrets
        $mailer->to($user->email)->send(new WelcomeMail($user));
    }
}

// config/queue.php — encrypt sensitive queues
'connections' => [
    'redis' => [
        'driver'  => 'redis',
        'encrypt' => true, // Laravel 9+ encrypts job payloads
    ],
],
```

---

## 13. Laravel Sanctum & Passport Security

**Vulnerability:** Sanctum API tokens stored in `localStorage` are vulnerable to XSS. Sanctum's SPA mode requires the `EnsureFrontendRequestsAreStateful` middleware for cookie-based auth, which is often misconfigured. Passport's `implicit` grant (deprecated) and client credentials stored insecurely enable token theft.

**References:** CWE-352, CWE-79, OWASP A07:2021

### Mandatory Rules

- **Use Sanctum SPA authentication (cookie-based)** for first-party SPAs — not personal access tokens stored in `localStorage`.
- **For Sanctum SPA mode**: configure `SANCTUM_STATEFUL_DOMAINS` correctly; call `GET /sanctum/csrf-cookie` before every state-changing request.
- **For Sanctum personal access tokens** (mobile/API): store tokens securely (encrypted storage, not `localStorage`); hash tokens at rest (`hash_token` is true by default in Laravel 10+).
- **For Passport**: disable the `implicit` grant — it is deprecated and leaks tokens in browser history. Use Authorization Code + PKCE.
- **Rotate Passport encryption keys** via `php artisan passport:keys` and back them up securely.
- **Scope Sanctum tokens** to the minimum required abilities — never issue tokens with `['*']` scope for non-admin operations.

```php
// ❌ INSECURE — Storing Sanctum token in localStorage (XSS steals it)
// JavaScript:
const token = await login(credentials);
localStorage.setItem('api_token', token); // accessible to any JS on the page

// ❌ INSECURE — Token with all abilities for a restricted operation
$token = $user->createToken('mobile-app', ['*']); // overly permissive

// ❌ INSECURE — Passport implicit grant enabled
// AuthServiceProvider:
Passport::enableImplicitGrant(); // deprecated, leaks tokens in redirect hash

// ✅ SECURE — Sanctum SPA: cookie-based (no token in JS)
// Frontend: call /sanctum/csrf-cookie first, then authenticate via session cookie
// config/sanctum.php
'stateful' => explode(',', env('SANCTUM_STATEFUL_DOMAINS', 'localhost,app.example.com')),

// ✅ SECURE — Scoped personal access tokens
$token = $user->createToken('invoice-reader', ['invoices:read', 'invoices:download']);
// In controller:
$request->user()->tokenCan('invoices:read') || abort(403);

// ✅ SECURE — Passport: Authorization Code + PKCE for SPAs
// AuthServiceProvider:
Passport::tokensExpireIn(now()->addMinutes(15));
Passport::refreshTokensExpireIn(now()->addDays(30));
// Enable PKCE on the client; do NOT enable implicit grant
```

---

## 14. Rate Limiting

**Vulnerability:** Without rate limiting, Laravel routes are vulnerable to brute-force on login, credential stuffing, enumeration of resources, and API abuse. Laravel's built-in throttle middleware uses `RateLimiter::for()`, but a single global rate limit is insufficient for authentication endpoints.

**References:** CWE-307, CWE-400, OWASP A04:2021

### Mandatory Rules

- **Apply the `throttle` middleware to all authentication routes** — configure a strict limit (5 attempts per minute per email+IP) in `RateLimiter::for('login')`.
- **Use Redis-backed cache** (`CACHE_DRIVER=redis`) for rate limiting in multi-server deployments — file/array cache is per-instance.
- **Define named rate limiters** in `RouteServiceProvider::configureRateLimiting()` and reference by name — do not use unnamed `throttle:60,1` on sensitive routes.
- **Apply different limits to registration, password reset, and email verification** endpoints — these are also abusable for enumeration.

```php
// ❌ INSECURE — No rate limiting on login
Route::post('/login', [AuthController::class, 'login']);

// ❌ INSECURE — Single global limit (60/min) applied to login route
Route::post('/login', [AuthController::class, 'login'])->middleware('throttle:60,1');

// ✅ SECURE — Named rate limiters in RouteServiceProvider
// app/Providers/RouteServiceProvider.php
protected function configureRateLimiting(): void {
    RateLimiter::for('login', function (Request $request) {
        return [
            Limit::perMinute(5)->by($request->input('email') . '|' . $request->ip()),
            Limit::perHour(20)->by($request->ip()),
        ];
    });

    RateLimiter::for('api', function (Request $request) {
        return $request->user()
            ? Limit::perMinute(60)->by($request->user()->id)
            : Limit::perMinute(20)->by($request->ip());
    });

    RateLimiter::for('password-reset', function (Request $request) {
        return Limit::perHour(5)->by($request->input('email') . '|' . $request->ip());
    });
}

// routes/web.php
Route::post('/login', [AuthController::class, 'login'])->middleware('throttle:login');
Route::post('/forgot-password', [PasswordController::class, 'store'])->middleware('throttle:password-reset');

// routes/api.php
Route::middleware(['auth:sanctum', 'throttle:api'])->group(function () {
    Route::apiResource('invoices', InvoiceController::class);
});
```

---

## 15. PHP Deserialization — unserialize() in Laravel Context

**Vulnerability:** Using PHP's `unserialize()` with user-controlled data in Laravel applications (e.g., cookie values, cache entries, API inputs) enables PHP Object Injection attacks via Property-Oriented Programming (POP) chains. Laravel's codebase contains many classes that form viable POP chains — any `unserialize()` call with user input is critical.

**References:** CWE-502, OWASP A08:2021, ysoserial-php gadget chains

### Mandatory Rules

- **Never call `unserialize()` on user-controlled data** — HTTP request bodies, cookies (except Laravel's encrypted cookies), query parameters, or data read from external sources.
- **Use `json_decode()` for data interchange** — it does not instantiate PHP objects.
- **Use `Cache::get()` safely** — Laravel encrypts session data, but custom cache reads with `unserialize()` on untrusted keys are dangerous.
- **Do not implement `__wakeup()`, `__destruct()`, or `Serializable::unserialize()`** in classes that hold sensitive logic unless absolutely necessary — minimize gadget availability.
- **Use `allowed_classes` in `unserialize()`** to restrict deserializable types if `unserialize()` cannot be avoided: `unserialize($data, ['allowed_classes' => [SafeClass::class]])`.

```php
// ❌ INSECURE — Unserializing user-controlled cookie/input
$preferences = unserialize(base64_decode($request->cookie('prefs')));
// attacker sends a serialized POP chain exploiting Laravel's own classes

// ❌ INSECURE — Unserializing data from an external queue
$data = unserialize($message->body); // queue message can be injected

// ✅ SECURE — Use JSON for data interchange
$preferences = json_decode($request->cookie('prefs'), true);
if (!is_array($preferences)) $preferences = []; // validate type

// ✅ SECURE — Laravel encrypted cookies (signed + encrypted, not raw serialize)
// Laravel's cookie middleware encrypts all cookies via Data Protection API
// Never bypass with: Cookie::queue(Cookie::make('name', $val, 0, '/', '', false, false))
//                                                                              ^ disables encryption

// ✅ SECURE — If unserialize is unavoidable, restrict allowed classes
$data = unserialize($trusted_string, ['allowed_classes' => [UserPreference::class]]);
```

---

## 16. Security Headers & Middleware Configuration

**Vulnerability:** Laravel does not set security headers by default. Without `Content-Security-Policy`, `X-Frame-Options`, `X-Content-Type-Options`, and `Strict-Transport-Security`, responses are vulnerable to clickjacking, MIME sniffing, XSS, and protocol downgrade attacks.

**References:** OWASP A05:2021, CWE-693

### Mandatory Rules

- **Add security headers via a custom middleware** registered in the `web` middleware group.
- **Set `X-Frame-Options: SAMEORIGIN` or `DENY`** — prevents clickjacking on Blade views.
- **Configure `Content-Security-Policy`** — `default-src 'self'`; tighten based on CDN, inline scripts, and style usage.
- **Set `Strict-Transport-Security`** with `max-age=31536000; includeSubDomains; preload` in production.
- **Remove `Server`, `X-Powered-By`** headers — do not reveal server technology.
- **Use the `spatie/laravel-csp` package** for rich CSP management with nonce support for inline scripts.

```php
// ✅ SECURE — Security headers middleware
// app/Http/Middleware/SecurityHeaders.php
class SecurityHeaders {
    public function handle(Request $request, Closure $next): Response {
        $response = $next($request);

        $response->headers->set('X-Content-Type-Options',  'nosniff');
        $response->headers->set('X-Frame-Options',         'SAMEORIGIN');
        $response->headers->set('X-XSS-Protection',        '0'); // rely on CSP
        $response->headers->set('Referrer-Policy',         'strict-origin-when-cross-origin');
        $response->headers->set('Permissions-Policy',
            'camera=(), microphone=(), geolocation=()');

        if (app()->environment('production')) {
            $response->headers->set('Strict-Transport-Security',
                'max-age=31536000; includeSubDomains; preload');
        }

        // Remove revealing headers
        $response->headers->remove('Server');
        $response->headers->remove('X-Powered-By');

        return $response;
    }
}

// bootstrap/app.php (Laravel 11) or app/Http/Kernel.php (Laravel 10)
$middleware->appendToGroup('web', SecurityHeaders::class);

// ✅ SECURE — spatie/laravel-csp for rich CSP with nonces
// config/csp.php: define policy class
// Blade: <script @cspNonce>...</script>
```

---

## 17. Debug Mode & Error Handling

**Vulnerability:** `APP_DEBUG=true` in production exposes full stack traces, environment variables, SQL queries with parameters, and application source code in HTTP error responses. Ignition (Laravel's debug interface) versions ≤ 2.5.1 allowed unauthenticated RCE via a file-write gadget (CVE-2021-3129).

**References:** CWE-209, CWE-497, CVE-2021-3129

### Mandatory Rules

- **Always set `APP_DEBUG=false` in production** — verify with `php artisan config:show app | grep debug`.
- **Upgrade Ignition** to ≥ 2.5.2 (or facade/ignition ≥ 1.16.15) to patch CVE-2021-3129.
- **Configure custom error pages** (`resources/views/errors/404.blade.php`, `500.blade.php`) — never expose framework error pages with stack traces.
- **Log errors to server-side channels** (daily log, Sentry, Flare) rather than returning them in HTTP responses.
- **Never log sensitive data** (passwords, tokens, PII) in any log channel.

```php
// ❌ INSECURE — Debug mode in production (exposes env vars, source code)
// .env
APP_DEBUG=true
// HTTP 500 response: full stack trace, .env variables, source code

// ✅ SECURE — Production error handling
// .env
APP_DEBUG=false
APP_ENV=production

// resources/views/errors/500.blade.php
<!DOCTYPE html>
<html><body>
    <h1>Something went wrong.</h1>
    <p>Please try again later. Reference: {{ $exception?->getCode() }}</p>
    <!-- No stack trace, no SQL, no env vars -->
</body></html>

// app/Exceptions/Handler.php — server-side logging only
public function register(): void {
    $this->reportable(function (Throwable $e) {
        // Sentry, Flare, etc.
        if (app()->bound('sentry')) {
            app('sentry')->captureException($e);
        }
    });

    // Never include exception details in JSON API responses in production
    $this->renderable(function (Throwable $e, Request $request) {
        if ($request->expectsJson() && !config('app.debug')) {
            return response()->json([
                'message' => 'Server Error',
                'request_id' => $request->header('X-Request-ID', Str::uuid()),
            ], 500);
        }
    });
}
```

---

## CVE Reference Table

| CVE | Severity | Component | Description | Fixed In |
|-----|----------|-----------|-------------|----------|
| CVE-2021-3129 | Critical (9.8) | Ignition (Facade/Ignition) ≤ 2.5.1 | Unauthenticated RCE via debug-mode file-write gadget — file-read via log viewer leads to Phar deserialization | 2.5.2 / facade/ignition 1.16.15 |
| CVE-2018-15133 | Critical (8.1) | Laravel Framework ≤ 5.6.29 | RCE via unencrypted or leaked `APP_KEY` — forged encrypted cookies trigger PHP unserialize with gadget chains | Laravel 5.6.30 |
| CVE-2024-52301 | High (8.7) | Laravel Framework ≤ 11.30.0 | Open redirect bypass in `redirect()->intended()` when `APP_URL` is not set — arbitrary URL redirect accepted | 11.31.0 / 10.x |
| CVE-2021-43617 | High (8.8) | Laravel Framework | Mass assignment via `forceFill()` allows privilege escalation when user input is not sanitized | Proper use of `$fillable` |
| CVE-2023-29568 | Medium (6.5) | Spatie Laravel Permission | SQL injection via `whereHas()` with user-controlled permission name — allows data exfiltration | 5.10.2 |
| CVE-2024-29291 | High (7.5) | Laravel Framework / Auth | Authentication bypass via `remember_token` manipulation in certain cookie configurations | Config hardening |
| CVE-2023-44388 | Medium (6.1) | Livewire ≤ 2.12.5 | Cross-site scripting via unescaped Livewire component properties rendered in Alpine.js | 2.12.6 |
| CVE-2022-40482 | High (7.5) | Laravel Passport ≤ 11.3.3 | Authorization code interception via open redirect in OAuth callback handling | 11.3.4 |
| CVE-2020-29040 | High (7.5) | Laravel DebugBar ≤ 3.5.1 | Information disclosure via exposed debug routes in non-debug environments | 3.6.0 |
| CVE-2019-10906 | High (8.1) | Jinja2 / Twig (used via Laravel Blade polyfills) | Server-Side Template Injection via user-controlled template strings | Avoid dynamic template compilation |

---

## Security Checklist

### Eloquent & Database
- [ ] No `whereRaw()`, `selectRaw()`, `orderByRaw()`, `havingRaw()` with string-interpolated user input — bindings array used
- [ ] No `DB::statement()`, `DB::select()` with string concatenation of user values
- [ ] Dynamic sort column validated against allowlist before `orderBy()`
- [ ] Sensitive queries scoped to authenticated user (`where('user_id', auth()->id())`)

### Mass Assignment
- [ ] All models define `$fillable` (not `$guarded = []`)
- [ ] `forceFill()` never called with request data
- [ ] `Model::create()` and `->fill()` only receive `$request->validated()` or `$request->only([...])`
- [ ] Sensitive fields (`is_admin`, `role`, `stripe_id`) excluded from `$fillable`

### Blade & XSS
- [ ] `{{ }}` used for all user-controlled output — no `{!! !!}` with unsanitized data
- [ ] Rich HTML sanitized with `mews/purifier` (HTMLPurifier) before `{!! !!}` or storage
- [ ] No `@php echo $var @endphp` with user content

### CSRF
- [ ] `@csrf` present in every HTML form
- [ ] `VerifyCsrfToken::$except` contains only webhook routes with signature verification
- [ ] `config/session.php`: `same_site` set to `'strict'` (or `'lax'` minimum)

### Authentication
- [ ] `RateLimiter::for('login')`: 5 attempts per minute per email+IP
- [ ] `$request->session()->regenerate()` called after successful login
- [ ] Passwords hashed with `Hash::make()` — no `md5()`, `sha1()`, custom hashing
- [ ] `Hash::check()` used for password verification — no `==` comparison
- [ ] `APP_DEBUG=false` in production
- [ ] Ignition / facade/ignition updated to patched version (CVE-2021-3129)

### Authorization
- [ ] Policy defined for each model accessible via HTTP
- [ ] `$this->authorize()` called in every controller method accessing a specific resource
- [ ] No authorization derived from `$request` parameters — auth identity from `Auth::user()`
- [ ] Eloquent queries scoped to current user for owned resources

### File Uploads
- [ ] `store()` used (random filename) — not `storeAs()` with `getClientOriginalName()`
- [ ] `mimetypes:` validation rule (magic bytes) used — not `mimes:` (extension only)
- [ ] Maximum file size enforced in validation and `php.ini`
- [ ] Uploads stored on `local` disk (not `public`) — served via signed URLs or controller

### Secrets & Environment
- [ ] `.env` in `.gitignore` — not committed to repository
- [ ] `APP_DEBUG=false` in production
- [ ] `APP_KEY` is a 32-byte base64 key (`php artisan key:generate`)
- [ ] `env()` calls only in `config/` files — `config()` used everywhere else
- [ ] No hardcoded secrets in any PHP file or config value

### Security Headers
- [ ] `SecurityHeaders` middleware registered in `web` group
- [ ] `X-Content-Type-Options: nosniff` set
- [ ] `X-Frame-Options: SAMEORIGIN` (or `DENY`) set
- [ ] `Strict-Transport-Security` set in production with `max-age` ≥ 1 year
- [ ] `Server` and `X-Powered-By` headers removed

### Open Redirect & SSRF
- [ ] `redirect()->intended()` used for post-login redirect — not `redirect($request->get('redirect'))`
- [ ] User-controlled URLs validated against hostname allowlist before `Http::get()`
- [ ] Private IP ranges blocked in outbound HTTP requests
- [ ] `Http::timeout(5)` set on all outbound calls

### Queue & Jobs
- [ ] No plaintext secrets in job payloads — IDs only, re-fetched in `handle()`
- [ ] `SerializesModels` trait used on jobs with Eloquent model properties
- [ ] Queue encryption enabled in `config/queue.php` for sensitive queues

### Rate Limiting
- [ ] Named rate limiters defined in `configureRateLimiting()`
- [ ] Login: 5 requests/minute per email+IP
- [ ] Password reset / registration: separate limits from general API
- [ ] Cache driver set to Redis in production for shared rate limiting

### Sanctum / Passport
- [ ] Sanctum SPA: cookie-based auth for first-party frontends — not localStorage tokens
- [ ] Sanctum tokens scoped to minimum required abilities — not `['*']`
- [ ] Passport implicit grant disabled (`Passport::enableImplicitGrant()` not called)
- [ ] Passport encryption keys backed up and rotated

### Supply Chain
- [ ] `composer audit` runs in CI — build fails on Critical/High advisories
- [ ] `composer.lock` committed and verified
- [ ] `roave/security-advisories` added as a dev dependency (prevents installing known-vulnerable packages)
- [ ] Laravel and all first-party packages on latest patch release

---

## Tooling

| Tool | Purpose | Command |
|------|---------|---------|
| [composer audit](https://getcomposer.org/doc/03-cli.md#audit) | Scan dependencies for known vulnerabilities | `composer audit` |
| [roave/security-advisories](https://github.com/Roave/SecurityAdvisories) | Block installation of packages with known CVEs | `composer require --dev roave/security-advisories:dev-latest` |
| [Enlightn](https://www.laravel-enlightn.com) | Static and dynamic security audit for Laravel | `php artisan enlightn` |
| [Larastan (PHPStan)](https://github.com/larastan/larastan) | Static analysis with Laravel-specific rules | `./vendor/bin/phpstan analyse` |
| [PHP_CodeSniffer + Security rules](https://github.com/FloeDesignTechnologies/phpcs-security-audit) | Security-focused coding standard checks | `phpcs --standard=Security app/` |
| [Semgrep PHP rules](https://semgrep.dev/r/php) | Custom and community security pattern matching | `semgrep --config=p/php` |
| [OWASP ZAP](https://owasp.org/www-project-zap/) | Dynamic application security testing (DAST) | `zap-cli quick-scan http://localhost:8000` |
| [mews/purifier](https://github.com/mewebstudio/Purifier) | HTMLPurifier integration for rich text sanitization | `composer require mews/purifier` |
| [spatie/laravel-csp](https://github.com/spatie/laravel-csp) | Content Security Policy management with nonces | `composer require spatie/laravel-csp` |
| [beyondcode/laravel-self-diagnosis](https://github.com/beyondcode/laravel-self-diagnosis) | Production configuration health checks | `php artisan self-diagnosis` |
| [nunomaduro/collision](https://github.com/nunomaduro/collision) | Better error reporting without exposing internals | `composer require nunomaduro/collision` |
