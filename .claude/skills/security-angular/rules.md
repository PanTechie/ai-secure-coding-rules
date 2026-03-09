# 🔺 Angular Security Rules

> **Standard:** Security rules for Angular 15+ applications including standalone components, SSR (Angular Universal), and progressive web apps.
> **Sources:** Angular Security Guide, OWASP Top 10:2025, CWE/MITRE, NVD/CVE Database, GitHub Advisory Database, Google Security Research, Snyk Angular Advisories
> **Version:** 1.0.0
> **Last updated:** March 2026
> **Scope:** Angular 15+ (standalone components, signals), Angular Universal / SSR, Angular Router, Angular HttpClient, Angular Forms (reactive and template-driven), Angular CLI, Angular Service Worker, common libraries (angular-oauth2-oidc, auth0-angular, @ngrx/store, @angular/material). React-specific rules are in `code-security-react.md`; general JavaScript/TypeScript rules are in `code-security-javascript.md`.

---

## General Instructions

Apply these rules when writing or reviewing Angular code. Angular's security model includes built-in sanitization for template bindings — but this protection is deliberately bypassed the moment you use any `bypassSecurityTrust*` method. Angular's distinct risk profile includes: **`DomSanitizer.bypassSecurityTrustHtml()` and its siblings are direct XSS sinks** — any value passed through them is rendered without sanitization; **Route Guards (`canActivate`, `canMatch`) are client-side JavaScript** — an attacker can bypass them by navigating directly; **`environment.ts` values are bundled into the client JS bundle** and visible to all users; **`HttpClientXsrfModule` protects only state-mutating requests** and requires the cookie name to match the server's configuration; and **Angular ReDoS vulnerabilities in built-in pipes (CVE-2023-26116, CVE-2023-26117)** affect applications using `TitleCasePipe` or similar pipes on user-controlled input in Angular < 16. Server-side access control must be enforced independently of client-side Angular guards.

---

## 1. `bypassSecurityTrust*` — Direct XSS Sinks

**Vulnerability:** Angular's `DomSanitizer` sanitizes all template values by default. The `bypassSecurityTrust*` methods (`bypassSecurityTrustHtml`, `bypassSecurityTrustScript`, `bypassSecurityTrustUrl`, `bypassSecurityTrustResourceUrl`, `bypassSecurityTrustStyle`) explicitly disable this sanitization. Any user-controlled string passed through these methods is rendered as raw HTML/script/URL and executes in the user's browser.

**References:** CWE-79, CWE-116, CVE-2024-21490

### Mandatory Rules

- **Never pass user-controlled or API-returned strings to any `bypassSecurityTrust*` method** — these methods are intended only for values you fully control at compile time (e.g., a known-safe icon SVG embedded in your source).
- **Use `DomSanitizer.sanitize(SecurityContext.HTML, value)` instead** when you must render HTML from a trusted internal source — this applies Angular's sanitization rather than bypassing it.
- **For rich user HTML, sanitize server-side with an allowlist library** (DOMPurify on the server or the Angular Universal context) before storing or rendering.
- **Audit all usages of `bypassSecurityTrust*` in code reviews** — treat each call as a security-critical annotation requiring explicit justification.
- **Use `SafeHtml`, `SafeUrl`, `SafeStyle`, `SafeResourceUrl` types** to make it visible in the type system where trust has been explicitly granted.

```typescript
// ❌ INSECURE — user-supplied HTML rendered without sanitization
@Component({
  template: `<div [innerHTML]="userHtml"></div>`,
})
export class CommentComponent {
  userHtml = this.sanitizer.bypassSecurityTrustHtml(this.route.snapshot.data['comment'].body);
  constructor(private sanitizer: DomSanitizer, private route: ActivatedRoute) {}
}

// ❌ INSECURE — URL from user profile bypasses sanitization
profileUrl = this.sanitizer.bypassSecurityTrustUrl(this.user.websiteUrl);

// ✅ SECURE — let Angular sanitize automatically; [innerHTML] sanitizes by default
@Component({
  template: `<div [innerHTML]="commentBody"></div>`,
})
export class CommentComponent {
  commentBody: string = this.route.snapshot.data['comment'].body;
  // Angular applies HTML sanitization automatically for [innerHTML]
}

// ✅ SECURE — only bypass for compile-time-known SVG icons, never user data
readonly safeIcon: SafeHtml;
constructor(private sanitizer: DomSanitizer) {
  // SECURITY: This SVG is authored by our team; it is not user-supplied.
  this.safeIcon = this.sanitizer.bypassSecurityTrustHtml(KNOWN_SAFE_ICON_SVG);
}
```

---

## 2. `[innerHTML]` Binding and DOM XSS — CVE-2024-21490

**Vulnerability:** Angular sanitizes `[innerHTML]` by default, but SVG-based bypasses have been found in specific Angular versions. CVE-2024-21490 (Angular < 17.1.0) allowed XSS via specially crafted SVG `animate` elements inside an `[innerHTML]` binding. Beyond Angular's own history, third-party Angular libraries sometimes set `innerHTML` directly via `ElementRef.nativeElement.innerHTML`, bypassing Angular's sanitization entirely.

**References:** CWE-79, CVE-2024-21490, CVE-2019-14863

### Mandatory Rules

- **Update Angular to ≥ 17.1.0** to patch CVE-2024-21490 (SVG-based XSS bypass in `[innerHTML]`).
- **Avoid direct DOM manipulation via `ElementRef.nativeElement.innerHTML = ...`** — this bypasses Angular's sanitization completely; use `[innerHTML]` binding instead.
- **Never use `Renderer2.setProperty(el, 'innerHTML', value)`** with user-supplied content — use Angular template bindings which go through the sanitizer.
- **Audit third-party Angular components** for direct `nativeElement.innerHTML` or `nativeElement.insertAdjacentHTML` usage — these are XSS sinks that bypass Angular's model.
- **Prefer Angular templates over direct DOM manipulation** — if you must manipulate the DOM directly (e.g., for animations), use `Renderer2` methods that do not set HTML content.

```typescript
// ❌ INSECURE — bypasses Angular sanitization entirely
@Component({ template: `<div #container></div>` })
export class WidgetComponent implements OnInit {
  @ViewChild('container') container!: ElementRef;

  ngOnInit() {
    this.container.nativeElement.innerHTML = this.userContent; // XSS
  }
}

// ❌ INSECURE — Renderer2 with innerHTML property
this.renderer.setProperty(this.el.nativeElement, 'innerHTML', userContent);

// ✅ SECURE — Angular template binding with built-in sanitization
@Component({
  template: `<div [innerHTML]="commentBody"></div>`,
})
export class CommentComponent {
  commentBody = this.sanitizer.sanitize(SecurityContext.HTML, this.rawContent) ?? '';
}

// ✅ SECURE — use textContent for plain text; no HTML parsing
this.renderer.setProperty(this.el.nativeElement, 'textContent', userContent);
```

---

## 3. URL Sanitization — `[href]`, `[src]`, `routerLink` with Untrusted URLs

**Vulnerability:** Angular sanitizes `[href]` and `[src]` bindings, blocking `javascript:` and `data:text/html` URIs by default. However, `bypassSecurityTrustUrl()` and `bypassSecurityTrustResourceUrl()` remove this protection. `[routerLink]` does not accept external URLs but `window.location.href = userUrl` does. Allowing users to supply avatar URLs or profile links without scheme validation enables open redirect and phishing.

**References:** CWE-79, CWE-601

### Mandatory Rules

- **Never pass user-supplied URLs to `bypassSecurityTrustUrl()` or `bypassSecurityTrustResourceUrl()`** — Angular's default `[href]` sanitization already handles safe URLs; bypassing it negates that protection.
- **Validate URL schemes before rendering in `[href]`, `[src]`, or navigation calls** — only allow `https://`, `http://`, and relative paths; reject `javascript:`, `data:`, `vbscript:`, and other schemes.
- **Never call `window.location.href = userInput` or `window.open(userInput)` without scheme validation** — Angular's template sanitizer does not protect imperative DOM assignments.
- **For external profile/website links, use a `safeExternalUrl` pipe** that validates the scheme before the value is bound.
- **Add `rel="noopener noreferrer"` to all `target="_blank"` anchor tags** to prevent tab-napping via `window.opener`.

```typescript
// ❌ INSECURE — user URL bypasses sanitization; javascript: executes on click
profileUrl = this.sanitizer.bypassSecurityTrustUrl(this.user.websiteUrl);
// template: <a [href]="profileUrl">Website</a>

// ❌ INSECURE — imperative navigation without validation
goToUserPage(url: string) {
  window.location.href = url; // open redirect / XSS
}

// ✅ SECURE — scheme validation pipe
@Pipe({ name: 'safeExternalUrl', standalone: true })
export class SafeExternalUrlPipe implements PipeTransform {
  private readonly SAFE = new Set(['https:', 'http:']);

  transform(url: string | null): string {
    if (!url) return '#';
    try {
      const parsed = new URL(url);
      return this.SAFE.has(parsed.protocol) ? url : '#';
    } catch {
      return url.startsWith('/') ? url : '#';
    }
  }
}
// template: <a [href]="user.websiteUrl | safeExternalUrl" rel="noopener noreferrer" target="_blank">
```

---

## 4. Angular XSRF/CSRF Protection — `HttpClientXsrfModule`

**Vulnerability:** Angular's `HttpClientXsrfModule` reads a CSRF token from a cookie (default: `XSRF-TOKEN`) and adds it as a request header (default: `X-XSRF-TOKEN`) on state-mutating requests (POST, PUT, PATCH, DELETE). If the cookie name does not match the server's expectation, or if the module is not imported, CSRF protection is absent. Requests to different origins are not protected by Angular's XSRF module.

**References:** CWE-352

### Mandatory Rules

- **Import `HttpClientXsrfModule.withOptions({ cookieName, headerName })`** in `AppModule` or `provideHttpClient(withXsrfConfiguration(...))` in standalone apps — ensure the cookie and header names match your server's CSRF configuration.
- **Never disable XSRF protection** by omitting the module or using `{ params: { skipXsrf: true } }` on state-mutating requests without a compensating control.
- **Set the XSRF cookie with `SameSite=Strict`** on the server side — this prevents the cookie from being sent in cross-origin requests, adding defense in depth.
- **Validate the XSRF token server-side** — Angular only sends the header; the server must verify it matches the cookie value.
- **Be aware that `HttpClientXsrfModule` does not protect cross-origin requests** — for APIs on a different domain, use a server-side CSRF mechanism (e.g., `Origin`/`Referer` header validation or an explicit API key).

```typescript
// ❌ INSECURE — no XSRF protection configured (standalone app)
export const appConfig: ApplicationConfig = {
  providers: [provideHttpClient()], // no XSRF configuration
};

// ❌ INSECURE — cookie/header names don't match server expectation
HttpClientXsrfModule.withOptions({
  cookieName: 'csrf-token',     // server expects 'XSRF-TOKEN'
  headerName: 'X-Csrf-Token',   // server expects 'X-XSRF-TOKEN'
})

// ✅ SECURE — standalone app with matching XSRF configuration
export const appConfig: ApplicationConfig = {
  providers: [
    provideHttpClient(
      withXsrfConfiguration({
        cookieName: 'XSRF-TOKEN',    // must match server Set-Cookie name
        headerName: 'X-XSRF-TOKEN', // must match server header validation
      }),
    ),
  ],
};
```

---

## 5. Route Guards — Client-Side Only; Server-Side Enforcement Required

**Vulnerability:** Angular Route Guards (`canActivate`, `canMatch`, `canLoad`) are client-side JavaScript that controls navigation within the browser. They do **not** prevent a determined attacker from accessing the underlying API data — an attacker can bypass them by calling the API directly, modifying JavaScript in DevTools, or using `router.navigate()` programmatically. Access control must be enforced server-side on every API request.

**References:** CWE-284, CWE-602

### Mandatory Rules

- **Treat Route Guards as UX, not security** — they improve user experience by redirecting unauthorized users, but they are not a security boundary.
- **Enforce access control on every API endpoint server-side** — never return sensitive data from an API just because the Angular route is "guarded".
- **Use `canMatch` (Angular 15+) instead of the deprecated `canLoad`** for lazy-loaded modules — `canMatch` prevents the module download; `canActivate` alone does not.
- **Never store authorization decisions in `localStorage`** as the sole source of truth for guards — a user can set `localStorage.setItem('isAdmin', 'true')` and bypass the guard.
- **Prefer server-rendered guards** (Angular Universal) or token-based validation in the guard that calls the server to verify access.

```typescript
// ❌ INSECURE — guard reads from localStorage; easily bypassed
@Injectable({ providedIn: 'root' })
export class AdminGuard implements CanActivate {
  canActivate(): boolean {
    return localStorage.getItem('isAdmin') === 'true'; // attacker sets this in DevTools
  }
}

// ❌ INSECURE — guard only; API does not check authorization
// app/admin/admin.component.ts
ngOnInit() {
  this.adminService.getAllUsers().subscribe(); // API returns data to anyone who calls it
}

// ✅ SECURE — guard calls server to verify; API also enforces auth
@Injectable({ providedIn: 'root' })
export class AdminGuard implements CanActivate {
  constructor(private authService: AuthService, private router: Router) {}

  canActivate(): Observable<boolean> {
    return this.authService.getCurrentUser().pipe(
      map(user => {
        if (user?.role === 'admin') return true;
        this.router.navigate(['/forbidden']);
        return false;
      }),
    );
    // API endpoint also validates the JWT role claim server-side
  }
}
```

---

## 6. Angular Universal (SSR) — State Transfer and Server-Side XSS

**Vulnerability:** Angular Universal renders components on the server and transfers state to the browser via `TransferState`. If user-controlled data is included in `TransferState` without serialization escaping, it can break out of the `<script>` tag containing the transfer state JSON (same as React SSR JSON injection). Additionally, server-side rendering evaluates component templates on the server — improper use of `bypassSecurityTrustHtml` in SSR context can execute malicious scripts during server rendering.

**References:** CWE-79, CWE-116

### Mandatory Rules

- **Use Angular's built-in `TransferState` API** (`makeStateKey`, `transferState.set/get`) for state hydration — it handles JSON serialization safely.
- **Never manually serialize Angular state into `<script>` tags** using `JSON.stringify` without an HTML-escape step — use `serialize-javascript` or Angular's transfer state mechanism.
- **Sanitize all user-controlled data before it enters SSR component state** — the same input validation rules apply server-side as client-side.
- **Set `Content-Security-Policy` headers at the Express/Node.js layer** serving Angular Universal — Next.js-style inline script nonces apply here too.
- **Avoid `isPlatformBrowser`/`isPlatformServer` guards as security controls** — they are runtime checks that affect behavior, not security boundaries.

```typescript
// ❌ INSECURE — manual state serialization; breaks on </script> in user data
// server.ts / Express handler
app.get('*', (req, res) => {
  const user = { name: req.query.name }; // user-controlled
  const html = indexHtml.replace(
    '</body>',
    `<script>window.__state__ = ${JSON.stringify(user)};</script></body>`,
  );
  res.send(html);
});

// ✅ SECURE — Angular TransferState handles serialization safely
// In a service
const USER_KEY = makeStateKey<User>('currentUser');

@Injectable()
export class UserService {
  constructor(private transferState: TransferState) {}

  setUser(user: User) {
    this.transferState.set(USER_KEY, user); // Angular serializes safely
  }
}
```

---

## 7. Environment Files — Client-Bundle Secret Leaks

**Vulnerability:** Angular's `environment.ts` / `environment.prod.ts` files are compiled into the client-side JavaScript bundle. Any values stored there (API keys, service account tokens, internal URLs, feature flag backends) are visible to every user via browser DevTools. Angular 15+ removed the dedicated `environment.ts` folder concept in some setups, but the underlying issue persists: any value in a file compiled by the Angular CLI is part of the browser bundle.

**References:** CWE-312, CWE-798

### Mandatory Rules

- **Never store secrets in `environment.ts` or `environment.prod.ts`** — treat all values there as public.
- **Move secret usage to a backend API** — the Angular app calls your API, and the API uses the secret internally.
- **Only store public configuration** (API base URLs, feature flag keys, analytics public IDs) in environment files.
- **Use `angular.json` `fileReplacements` correctly** — verify that production environment files do not include development-only debug flags that leak internal information.
- **Audit environment files in CI** — add a check that fails the build if values matching secret patterns (`KEY`, `SECRET`, `PASSWORD`, `TOKEN`, `PRIVATE`) appear in any `environment.*.ts` file.

```typescript
// ❌ INSECURE — bundled into browser JavaScript; visible to all users
// environment.prod.ts
export const environment = {
  production: true,
  stripeSecretKey: 'sk_live_...',      // EXPOSED in browser bundle
  openAiApiKey: 'sk-proj-...',         // EXPOSED
  databaseUrl: 'postgresql://...',     // EXPOSED
};

// ✅ SECURE — only public values in environment files
// environment.prod.ts
export const environment = {
  production: true,
  apiUrl: 'https://api.example.com',         // safe: public endpoint
  stripePublishableKey: 'pk_live_...',       // safe: publishable key
  analyticsId: 'UA-XXXXXXXX-1',             // safe: public ID
};
// Secrets live only in backend server environment variables
```

---

## 8. Angular HTTP Interceptors — Auth Token Handling

**Vulnerability:** A common pattern attaches Bearer tokens from `localStorage` to every outgoing `HttpClient` request via an interceptor. If the token is stored in `localStorage` (XSS-accessible), any XSS vulnerability in the app or a dependency can exfiltrate the token. Interceptors that forward credentials to cross-origin requests also expose tokens to third-party APIs.

**References:** CWE-312, CWE-319

### Mandatory Rules

- **Store authentication tokens in `httpOnly; Secure; SameSite=Strict` cookies** — cookies with `httpOnly` are inaccessible to JavaScript interceptors and to XSS payloads.
- **If tokens must be in memory** (in-memory store, NgRx state), never persist them to `localStorage` or `sessionStorage` — lose them on page refresh and re-authenticate.
- **Scope credential forwarding in interceptors** — only add `Authorization` headers to requests targeting your own API domain; never forward credentials to third-party URLs.
- **Implement token refresh logic with a mutex** — a race condition in token refresh can result in parallel 401s and token invalidation loops that lock users out.
- **Clear all auth state on logout** — call the backend logout endpoint (which invalidates the server-side session/token), then clear in-memory state.

```typescript
// ❌ INSECURE — token from localStorage; XSS can steal it; forwarded to all origins
@Injectable()
export class AuthInterceptor implements HttpInterceptor {
  intercept(req: HttpRequest<unknown>, next: HttpHandler): Observable<HttpEvent<unknown>> {
    const token = localStorage.getItem('access_token'); // XSS-accessible
    const cloned = req.clone({ setHeaders: { Authorization: `Bearer ${token}` } });
    return next.handle(cloned); // forwarded to ALL requests including third-party CDN calls
  }
}

// ✅ SECURE — token from in-memory store; only forwarded to own API
@Injectable()
export class AuthInterceptor implements HttpInterceptor {
  constructor(private authStore: AuthStore, private env: EnvironmentService) {}

  intercept(req: HttpRequest<unknown>, next: HttpHandler): Observable<HttpEvent<unknown>> {
    const isOwnApi = req.url.startsWith(this.env.apiUrl); // scope to own domain only
    if (!isOwnApi) return next.handle(req);

    const token = this.authStore.getAccessToken(); // in-memory; not localStorage
    if (!token) return next.handle(req);

    return next.handle(req.clone({ setHeaders: { Authorization: `Bearer ${token}` } }));
  }
}
```

---

## 9. ReDoS via Angular Built-in Pipes — CVE-2023-26116 / CVE-2023-26117

**Vulnerability:** Angular < 16.0.0 contained ReDoS vulnerabilities in built-in pipes: `TitleCasePipe` (CVE-2023-26117) and `UpperCasePipe`/`LowerCasePipe` with `lang` attribute (CVE-2023-26116) were vulnerable to catastrophic backtracking when processing specially crafted strings. Applying these pipes to user-controlled input allowed denial of service.

**References:** CWE-1333, CVE-2023-26116, CVE-2023-26117, CVE-2023-26118

### Mandatory Rules

- **Update Angular to ≥ 16.0.0** to patch the `TitleCasePipe` and `lang`-based pipe ReDoS vulnerabilities.
- **Limit input length before applying pipes to user-controlled strings** — even with the fix, bounding input length is good defense-in-depth practice.
- **Avoid applying `AsyncPipe` to Observables derived from user input without debouncing** — rapid emissions can overload the change detection cycle.
- **Test pipes with long repetitive strings** (e.g., `'a'.repeat(100000)`) in development to detect ReDoS before production.

```typescript
// ❌ INSECURE — TitleCasePipe on user input; ReDoS on Angular < 16
// template: <span>{{ userInput | titlecase }}</span>

// ✅ SECURE — update Angular to ≥ 16 + input length guard in component
@Component({
  template: `<span>{{ safeName | titlecase }}</span>`,
})
export class NameComponent {
  @Input() set name(value: string) {
    this.safeName = value.slice(0, 200); // bound length before pipe
  }
  safeName = '';
}
```

---

## 10. Open Redirect via Angular Router

**Vulnerability:** Using user-controlled values in `router.navigate()`, `router.navigateByUrl()`, or `<a [routerLink]="userValue">` can redirect users to external malicious sites. While Angular Router only handles routes within the app by default, `router.navigateByUrl('//evil.com')` or `window.location.href = queryParam` allows external redirects.

**References:** CWE-601

### Mandatory Rules

- **Never pass URL query parameters or route params directly to `router.navigate()` or `router.navigateByUrl()`** without validating they are relative paths within the app.
- **Validate `returnUrl` or `redirect` query parameters** against a list of known app routes before redirecting after login.
- **Sanitize all values bound to `[routerLink]`** — while `routerLink` is generally safe for internal routing, validate dynamic segments that come from API responses or user input.
- **Use Angular's `Router.url` and `ActivatedRoute.snapshot.url`** to construct safe back-navigation rather than trusting external values.

```typescript
// ❌ INSECURE — open redirect after login: ?returnUrl=//evil.com
@Component({...})
export class LoginComponent {
  constructor(private router: Router, private route: ActivatedRoute) {}

  onLoginSuccess() {
    const returnUrl = this.route.snapshot.queryParams['returnUrl'];
    this.router.navigateByUrl(returnUrl); // redirects to evil.com
  }
}

// ✅ SECURE — validate returnUrl is a relative app path
onLoginSuccess() {
  const returnUrl = this.route.snapshot.queryParams['returnUrl'] ?? '/dashboard';
  // Only allow relative paths that don't start with //
  const safeUrl = returnUrl.startsWith('/') && !returnUrl.startsWith('//')
    ? returnUrl
    : '/dashboard';
  this.router.navigateByUrl(safeUrl);
}
```

---

## 11. Content Security Policy for Angular Applications

**Vulnerability:** Without CSP, any XSS vector (injected script, compromised dependency) can execute unlimited JavaScript. Angular applications are particularly challenging for CSP because Angular historically relied on dynamic style generation; Angular 15+ added nonce-based CSP support for styles, reducing the need for `unsafe-inline`.

**References:** CWE-79, CWE-1021

### Mandatory Rules

- **Set `Content-Security-Policy` headers on the server serving your Angular app** — Angular CLI's dev server does not set CSP headers; configure them in nginx, Express, or your CDN.
- **Use Angular 16+ nonce-based style CSP** — Angular supports `ngCspNonce` to inject a server-generated nonce into component styles, eliminating the need for `style-src 'unsafe-inline'`.
- **Avoid `script-src 'unsafe-eval'`** — Angular's Ahead-of-Time (AoT) compilation eliminates the need for `eval()`; if you see `unsafe-eval` in your CSP, you likely have a JIT compilation dependency.
- **Add `frame-ancestors 'none'`** to prevent clickjacking attacks on Angular SPA pages.
- **Test your CSP** with Angular's `ng serve` proxy or a local nginx before deploying.

```html
<!-- Set via HTTP response header on the server (nginx/Express) -->

<!-- ❌ INSECURE — allows eval and all inline scripts -->
Content-Security-Policy: default-src *; script-src * 'unsafe-eval' 'unsafe-inline'

<!-- ✅ SECURE — strict CSP for AoT-compiled Angular app -->
Content-Security-Policy:
  default-src 'self';
  script-src 'self';
  style-src 'self' 'nonce-REPLACE_NONCE';
  img-src 'self' data: https:;
  font-src 'self';
  connect-src 'self' https://api.example.com;
  frame-ancestors 'none';
  form-action 'self';
```

```typescript
// Angular 16+ nonce support — pass server-generated nonce to the app
// index.html
// <app-root ngCspNonce="REPLACE_NONCE"></app-root>

// app.config.ts (standalone)
bootstrapApplication(AppComponent, {
  providers: [
    {
      provide: CSP_NONCE,
      useValue: document.querySelector('app-root')?.getAttribute('ngcspnonce'),
    },
  ],
});
```

---

## 12. NgRx / State Management — Sensitive Data in Store

**Vulnerability:** NgRx store state is inspectable via the Redux DevTools browser extension. Storing authentication tokens, passwords, credit card data, or PII in the NgRx store exposes this data to anyone with access to the browser's DevTools. State serialized for server-side rendering or hydration may also expose sensitive values.

**References:** CWE-312, CWE-532

### Mandatory Rules

- **Never store plaintext passwords, private keys, or full payment card data in NgRx/Akita/NGXS store state** — pass them directly to services and discard.
- **Store only non-sensitive user metadata** in the store (user ID, display name, role) — not tokens or session secrets.
- **Disable Redux DevTools in production** — use `!isDevMode()` or `process.env.NODE_ENV !== 'production'` as the guard for `StoreDevtoolsModule`.
- **Configure `StoreDevtoolsModule` with `maxAge`** to limit the number of stored actions (reduces exposure window if DevTools are accidentally left enabled).
- **Sanitize state before serialization** for SSR/hydration — strip sensitive fields before `TransferState.set()`.

```typescript
// ❌ INSECURE — token and password in NgRx state; visible in Redux DevTools
export const authReducer = createReducer(
  initialState,
  on(loginSuccess, (state, { token, refreshToken, password }) => ({
    ...state, token, refreshToken, password, // all visible in DevTools
  })),
);

// ❌ INSECURE — DevTools enabled in production
StoreDevtoolsModule.instrument({ maxAge: 25 })

// ✅ SECURE — only non-sensitive data in store; DevTools disabled in production
export interface AuthState {
  userId: string | null;
  displayName: string | null;
  role: 'user' | 'admin' | null;
  // no token, no password
}

// app.module.ts / app.config.ts
StoreDevtoolsModule.instrument({ maxAge: 25, logOnly: !isDevMode() })
// or conditionally import:
isDevMode() ? StoreDevtoolsModule.instrument({ maxAge: 25 }) : []
```

---

## 13. OAuth / OIDC Integration Security (angular-oauth2-oidc, auth0-angular)

**Vulnerability:** OAuth/OIDC in Angular SPAs requires careful token storage, PKCE enforcement, and redirect URI validation. Storing access tokens in `localStorage` exposes them to XSS; missing PKCE allows authorization code interception attacks; permissive redirect URI registration in the authorization server allows token theft via open redirect.

**References:** CWE-287, CWE-601, OAuth Security BCP (RFC 9700)

### Mandatory Rules

- **Use PKCE (Proof Key for Code Exchange)** for all Authorization Code flows — `angular-oauth2-oidc` supports this via `useSilentRefresh: false` with `responseType: 'code'`.
- **Store tokens in memory (service property) or `sessionStorage`** — prefer in-memory; avoid `localStorage` as tokens in `localStorage` survive XSS and page reloads.
- **Register exact redirect URIs** in your authorization server — never use wildcard or pattern-matching redirect URIs; register `https://app.example.com/callback` exactly.
- **Validate the `state` parameter** on OAuth callback to prevent CSRF during the OAuth flow — `angular-oauth2-oidc` does this automatically when `state` is configured.
- **Validate `id_token` claims** (`iss`, `aud`, `exp`, `nonce`) before trusting the identity — use the library's built-in validation, not manual JWT decoding.
- **Use short-lived access tokens** (< 15 minutes) with silent refresh via an `httpOnly` refresh token cookie.

```typescript
// ❌ INSECURE — no PKCE; implicit flow (deprecated); tokens in localStorage
const authConfig: AuthConfig = {
  responseType: 'token id_token', // implicit flow — deprecated and insecure
  // no PKCE; no state validation
};

// ❌ INSECURE — manually storing token in localStorage
this.oauthService.events.subscribe(e => {
  if (e.type === 'token_received') {
    localStorage.setItem('access_token', this.oauthService.getAccessToken());
  }
});

// ✅ SECURE — PKCE; authorization code flow; no manual localStorage storage
const authConfig: AuthConfig = {
  issuer: 'https://auth.example.com',
  redirectUri: window.location.origin + '/callback',
  clientId: 'my-angular-app',
  responseType: 'code',           // Authorization Code flow
  scope: 'openid profile email',
  requireHttps: true,
  showDebugInformation: false,    // disable in production
  sessionChecksEnabled: true,
  // angular-oauth2-oidc handles PKCE automatically for 'code' responseType
};
// Library manages tokens internally; do not copy to localStorage
```

---

## 14. Angular Service Worker — Cache Security

**Vulnerability:** Angular's `@angular/service-worker` caches assets and API responses for offline use. Misconfigured caching (caching authenticated API responses, caching stale sensitive data, or caching error responses) can serve stale authenticated content to different users on shared devices. Service worker registration on HTTP (non-HTTPS) origins is also a security risk.

**References:** CWE-345, CWE-312

### Mandatory Rules

- **Never cache authenticated API responses** in `ngsw-config.json` — only cache public, static assets and unauthenticated API data.
- **Use `freshness` strategy** (not `performance`) for any data that changes frequently or contains user-specific content.
- **Serve the Angular app exclusively over HTTPS** — service workers require HTTPS; HTTP service workers are a downgrade attack vector.
- **Set cache expiration (`maxAge`) on all `dataGroups`** — without expiration, the service worker serves stale data indefinitely.
- **Test service worker behavior** on cache invalidation after logout — confirm that protected routes show fresh data after re-authentication.

```json
// ❌ INSECURE — caches authenticated API responses
{
  "dataGroups": [{
    "name": "api",
    "urls": ["/api/**"],          // caches all API calls including auth-required ones
    "cacheConfig": { "strategy": "performance", "maxSize": 100 }
  }]
}

// ✅ SECURE — only cache public, unauthenticated assets
{
  "dataGroups": [{
    "name": "public-api",
    "urls": ["/api/public/**"],   // only unauthenticated endpoints
    "cacheConfig": {
      "strategy": "freshness",
      "maxSize": 50,
      "maxAge": "1h",
      "timeout": "5s"
    }
  }]
}
```

---

## 15. Production Build Hardening — Source Maps, AOT, and `--configuration=production`

**Vulnerability:** Building Angular without the production configuration (`--configuration=production`) may include source maps, enable debug logging, use JIT compilation (which requires `eval()`), and disable minification. Source maps expose original TypeScript source to all users. Debug logging may include sensitive data.

**References:** CWE-540, CWE-532

### Mandatory Rules

- **Always build for production using `ng build --configuration=production`** — this enables AoT compilation, minification, tree-shaking, and disables source maps by default.
- **Set `sourceMap: false` in `angular.json` under the production configuration** — verify source maps are not generated or served in production.
- **Remove all `console.log`, `console.debug`, and `console.warn` statements in production** — use a logging service that no-ops in production or set `enableProdMode()`.
- **Call `enableProdMode()` in `main.ts`** for Angular versions < 17 — this disables double change-detection checks and some diagnostic output.
- **Never use `--disable-host-check`** with `ng serve` on shared or CI environments — this allows DNS rebinding attacks against the dev server.
- **Restrict Angular DevTools browser extension access** in production by calling `disableDebugTools()` from `@angular/platform-browser`.

```typescript
// ❌ INSECURE — JIT compilation; dev mode enabled; debug tools accessible
// main.ts
platformBrowserDynamic().bootstrapModule(AppModule); // JIT; needs unsafe-eval CSP

// ❌ INSECURE — source maps enabled in angular.json production config
// angular.json
"production": {
  "sourceMap": true, // source code exposed to all users
  "optimization": false
}

// ✅ SECURE — AoT compilation; prod mode; debug tools disabled
// main.ts
import { disableDebugTools } from '@angular/platform-browser';
if (environment.production) {
  enableProdMode();
}
bootstrapApplication(AppComponent, appConfig).then(appRef => {
  if (environment.production) {
    disableDebugTools();
  }
});

// angular.json — production configuration
"production": {
  "optimization": true,
  "sourceMap": false,
  "aot": true,
  "buildOptimizer": true,
  "namedChunks": false
}
```

---

## CVE Reference Table

| CVE | Severity | Component | Description | Fixed In |
|-----|----------|-----------|-------------|----------|
| CVE-2024-21490 | High (8.2) | `@angular/core` < 17.1.0 | XSS via crafted SVG `animate` element in `[innerHTML]` binding bypasses Angular's sanitization | Angular 17.1.0 |
| CVE-2023-26117 | Medium (5.3) | `@angular/core` < 16.0.0 | ReDoS in `TitleCasePipe` via specially crafted unicode string | Angular 16.0.0 |
| CVE-2023-26116 | Medium (5.3) | `@angular/core` < 16.0.0 | ReDoS in `UpperCasePipe`/`LowerCasePipe` with `lang` attribute via crafted string | Angular 16.0.0 |
| CVE-2023-26118 | Medium (5.3) | `@angular/core` < 16.0.0 | ReDoS in scroll strategy via crafted `Window` position string | Angular 16.0.0 |
| CVE-2022-25869 | Medium (6.1) | `@angular/core` < 13.3.5 | XSS via `ng-attr-` binding with specific HTML attributes not sanitized correctly | Angular 13.3.5 |
| CVE-2019-14863 | Medium (6.1) | `@angular/core` < 8.2.14 | XSS via SVG `animate` element in templates bypasses Angular compiler sanitization | Angular 8.2.14, 9.0.0-rc |
| CVE-2021-41184 | Medium (6.1) | `jquery-ui` (used by some Angular projects) | XSS via `.position()` method; common transitive dependency | jquery-ui 1.13.0 |
| CVE-2022-33987 | Medium (5.9) | `got` ≤ 11.8.4 (Angular CLI transitive dep) | SSRF via `unix://` protocol in URL | got 12.1.0 |
| GHSA-3p37-3636-q8wv | High (8.1) | `angular-oauth2-oidc` < 12.3.0 | Missing PKCE state parameter validation allows CSRF during OAuth callback | angular-oauth2-oidc 12.3.0 |
| GHSA-j8r2-6x86-q33q | Medium (5.4) | `@auth0/auth0-angular` < 1.8.3 | Stored XSS via error message displayed without encoding during authentication failure | auth0-angular 1.8.3 |

---

## Security Checklist

### Critical Updates
- [ ] Angular ≥ 17.1.0 (CVE-2024-21490 — SVG XSS in `[innerHTML]`)
- [ ] Angular ≥ 16.0.0 (CVE-2023-26116/26117/26118 — ReDoS in pipes)
- [ ] angular-oauth2-oidc ≥ 12.3.0 (missing PKCE state validation)

### XSS Prevention
- [ ] No `bypassSecurityTrust*` methods called with user-controlled or API-returned data
- [ ] Each `bypassSecurityTrust*` call has a `// SECURITY:` comment justifying it
- [ ] No `nativeElement.innerHTML` direct assignment with user content
- [ ] URL scheme validated before rendering in `[href]`/`[src]`
- [ ] All `target="_blank"` links have `rel="noopener noreferrer"`

### CSRF
- [ ] `provideHttpClient(withXsrfConfiguration(...))` configured in standalone apps
- [ ] Cookie name and header name match server-side CSRF configuration
- [ ] XSRF cookie set with `SameSite=Strict` on server

### Route Guards
- [ ] Guards treated as UX only; API endpoints enforce auth independently
- [ ] `canMatch` used instead of deprecated `canLoad` (Angular 15+)
- [ ] Guard does not rely on `localStorage` as sole auth source

### Environment Variables
- [ ] No secrets in `environment.ts` or `environment.prod.ts`
- [ ] Only public configuration values in Angular environment files

### Authentication
- [ ] Tokens stored in `httpOnly` cookies or in-memory (not `localStorage`)
- [ ] HTTP interceptor scoped to own API domain only
- [ ] Auth state cleared completely on logout (server + client)

### OAuth/OIDC
- [ ] PKCE enabled for Authorization Code flow
- [ ] Exact redirect URIs registered (no wildcards)
- [ ] `state` parameter validated on callback
- [ ] `id_token` claims (`iss`, `aud`, `exp`, `nonce`) validated

### State Management
- [ ] Redux DevTools disabled in production (`!isDevMode()`)
- [ ] No tokens, passwords, or PII in NgRx/Akita/NGXS store
- [ ] `StoreDevtoolsModule.instrument({ logOnly: !isDevMode() })` configured

### Service Worker
- [ ] No authenticated API endpoints in `ngsw-config.json` `dataGroups`
- [ ] `maxAge` set on all cached data groups
- [ ] App served over HTTPS only

### Production Build
- [ ] `ng build --configuration=production` used in CI/CD
- [ ] `sourceMap: false` in production `angular.json` config
- [ ] `disableDebugTools()` called in production
- [ ] No `console.log` with sensitive data in production code
- [ ] `--disable-host-check` never used on shared/CI environments

### Content Security Policy
- [ ] CSP headers set at server level (nginx/Express)
- [ ] No `unsafe-eval` (AoT compilation eliminates this requirement)
- [ ] Angular 16+ `ngCspNonce` used for style nonce
- [ ] `frame-ancestors 'none'` set

### Dependencies
- [ ] `npm audit` runs in CI with zero critical/high findings
- [ ] New `ngx-*` libraries audited before adoption
- [ ] All Angular packages updated to the same major version

---

## Tooling

| Tool | Purpose | Command |
|------|---------|---------|
| [npm audit](https://docs.npmjs.com/cli/v10/commands/npm-audit) | Checks installed packages for known CVEs including Angular packages | `npm audit --audit-level=high` |
| [Snyk](https://snyk.io) | Dependency and code vulnerability scanning | `npx snyk test` |
| [Angular ESLint](https://github.com/angular-eslint/angular-eslint) | Linting rules for Angular-specific anti-patterns | `ng lint` |
| [ng build --stats-json](https://angular.io/cli/build) | Analyze bundle contents; verify no secrets embedded | `npx webpack-bundle-analyzer dist/stats.json` |
| [securityheaders.com](https://securityheaders.com) | Validate CSP and other security headers for Angular app | Web UI |
| [OWASP ZAP](https://www.zaproxy.org/) | Dynamic application security testing (DAST) for Angular SPAs | `zap-baseline.py -t https://app.example.com` |
| [Semgrep Angular rules](https://semgrep.dev/r?lang=typescript&search=angular) | Static analysis for Angular security anti-patterns | `semgrep --config=r/typescript.angular .` |
| [Angular DevTools](https://angular.io/guide/devtools) | Browser extension for debugging; verify disabled in production via `disableDebugTools()` | Chrome Extension |
