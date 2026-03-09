# ⚡ Vue.js Security Rules

> **Standard:** Vue 3.x / Nuxt 3.x secure development rules covering XSS, SSRF, state leakage, CSP, open redirect, prototype pollution, and supply chain security.
> **Sources:** Vue.js Security Guide, Nuxt Security Module Docs, OWASP Top 10:2025, CWE/MITRE, NVD, GitHub Advisory Database, Snyk Vue Security Advisories
> **Version:** 1.0.0
> **Last updated:** March 2026
> **Scope:** Vue 3.x (Composition API & Options API), Pinia, Vue Router 4, Vite, and Nuxt 3.x (SSR, server routes, useFetch). Vue 2.x patterns noted where they differ.

---

## General Instructions

Apply these rules when generating, reviewing, or refactoring any Vue.js or Nuxt.js code. The most dangerous Vue-specific vulnerability is **`v-html` XSS** — it is the direct equivalent of React's `dangerouslySetInnerHTML` and the leading source of XSS in Vue applications. The second most common critical is **template compilation from user-controlled strings**, which enables server-side template injection (SSTI) equivalent to `eval()` for arbitrary JavaScript execution. For Nuxt.js SSR apps, **state hydration XSS** and **`useRuntimeConfig()` secret exposure** are equally critical. Always validate on the server; Vue component validation is UI-only.

---

## 1. `v-html` XSS — Sanitize Before Rendering

**Vulnerability:** `v-html` injects raw HTML into the DOM without any escaping, making it the primary XSS sink in Vue applications. An attacker-controlled string rendered with `v-html` executes arbitrary JavaScript. Vue's template auto-escaping applies to `{{ }}` interpolations only — `v-html` bypasses it entirely.

**References:** CWE-79, OWASP A03:2025, Vue Security Guide §HTML Content, CVE-2024-6783

### Mandatory Rules

- **Never pass unsanitized user input to `v-html`** — treat it the same as `innerHTML`; any user-controlled string reaching this directive is an XSS vulnerability.
- **Sanitize with DOMPurify before every `v-html` binding** — use `DOMPurify.sanitize(content, { USE_PROFILES: { html: true } })` and configure the allowlist for your use case.
- **Create a `v-safe-html` custom directive** that wraps DOMPurify and use it instead of `v-html` throughout the codebase.
- **Prefer `{{ }}` text interpolation over `v-html`** for displaying user content — Vue auto-escapes `{{ }}` bindings.
- **Set a strict CSP** with `script-src 'self'` to limit XSS impact even if `v-html` is misused.

```vue
<!-- ❌ INSECURE — XSS: attacker controls content, arbitrary JS execution -->
<div v-html="userPost.body"></div>
<div v-html="$route.query.message"></div>

<!-- ✅ SECURE — sanitize first with DOMPurify -->
<script setup>
import DOMPurify from 'dompurify';
const safeBody = computed(() => DOMPurify.sanitize(userPost.value.body));
</script>
<div v-html="safeBody"></div>

<!-- ✅ SECURE — custom directive that always sanitizes -->
<!-- directives/v-safe-html.ts -->
import DOMPurify from 'dompurify';
export const vSafeHtml = {
  mounted(el: HTMLElement, binding: { value: string }) {
    el.innerHTML = DOMPurify.sanitize(binding.value);
  },
  updated(el: HTMLElement, binding: { value: string }) {
    el.innerHTML = DOMPurify.sanitize(binding.value);
  },
};
// Usage:
<div v-safe-html="userPost.body"></div>
```

---

## 2. URL Protocol Injection — Block `javascript:` in `:href` / `:src`

**Vulnerability:** Dynamic `:href`, `:src`, and `:action` bindings with user-controlled URLs allow `javascript:alert(1)` injection. Vue does not sanitize URL attribute bindings. This is a persistent XSS vector when user-supplied URLs are stored and later rendered.

**References:** CWE-79, CWE-601, OWASP A03:2025, Vue Security Guide §URL Injection

### Mandatory Rules

- **Validate all dynamic URL bindings against an allowlist of protocols** — allow only `https:` and `http:` (and `mailto:` if needed).
- **Create a `safeUrl` computed or helper** that returns `undefined` (rendering no attribute) for disallowed protocols.
- **Never use `:href="$route.query.url"` or `:src="$route.query.img"` without validation** — query parameters are fully attacker-controlled.
- **Apply the same validation to `router-link :to` bindings** when `:to` is constructed from user input.

```vue
<!-- ❌ INSECURE — javascript: href XSS -->
<a :href="userProfile.website">Visit</a>
<img :src="$route.query.avatar" />

<!-- ✅ SECURE — validate protocol before binding -->
<script setup>
function safeUrl(url: string | undefined): string | undefined {
  if (!url) return undefined;
  try {
    const parsed = new URL(url);
    return ['https:', 'http:'].includes(parsed.protocol) ? url : undefined;
  } catch {
    return undefined;
  }
}
const safeWebsite = computed(() => safeUrl(userProfile.value.website));
</script>
<a :href="safeWebsite">Visit</a>

<!-- ✅ SECURE — also apply to router-link :to with external redirects -->
<router-link :to="safeRedirect(route.query.next)">Continue</router-link>
```

---

## 3. Template Compilation from User Input — SSTI / Code Execution

**Vulnerability:** `Vue.compile()`, `compileToFunction()`, or dynamically creating a component from a user-supplied string template executes arbitrary JavaScript — this is equivalent to `eval()`. Any user-controlled template string reaching the Vue compiler is a critical RCE/XSS vulnerability.

**References:** CWE-94, CWE-79, OWASP A03:2025, Vue Security Guide §Rendering Functions

### Mandatory Rules

- **Never call `Vue.compile()`, `compileToFunction()`, or `defineComponent({ template: userInput })`** with any string derived from user input, database content, or external APIs.
- **Never use the runtime-only build** for server-rendered pages that use templates built from user data — always pre-compile templates at build time.
- **Use render functions (`h()`)** for dynamic component creation when the component structure is user-influenced, not template strings.
- **Avoid `<component :is="dynamicName">` with user-controlled strings** — restrict dynamic component names to an explicit allowlist of registered components.

```typescript
// ❌ INSECURE — SSTI: arbitrary JS execution via Vue compiler
const userTemplate = `<div>{{ ${userInput} }}</div>`;
const DynamicComp = Vue.compile(userTemplate);

// ❌ INSECURE — dynamic component from user-controlled name
const compName = route.query.widget; // attacker controls
<component :is="compName" />

// ✅ SECURE — allowlist of pre-compiled components
const ALLOWED_WIDGETS = { chart: ChartWidget, table: TableWidget } as const;
const widget = ALLOWED_WIDGETS[route.query.widget as keyof typeof ALLOWED_WIDGETS];
<component :is="widget ?? FallbackWidget" />

// ✅ SECURE — render function for truly dynamic structures (no template compilation)
import { h } from 'vue';
const SafeCard = defineComponent({
  props: ['title', 'body'],
  render() {
    return h('div', { class: 'card' }, [
      h('h2', this.title),   // auto-escaped
      h('p', this.body),     // auto-escaped
    ]);
  },
});
```

---

## 4. Pinia / Vuex Sensitive Data in State

**Vulnerability:** Pinia and Vuex stores are accessible via Vue DevTools in development and via `window.__pinia` / `window.__vue_store__` if not hardened in production. Storing raw passwords, full credit card numbers, SSNs, or private keys in global state exposes them to any component, any third-party script (XSS), and browser extension inspection.

**References:** CWE-312, CWE-359, OWASP A02:2025

### Mandatory Rules

- **Never store raw credentials, private keys, or full payment card data in Pinia/Vuex state** — keep only masked representations or IDs.
- **Store JWTs in `HttpOnly` cookies, not in Pinia state** — state is accessible via XSS; `HttpOnly` cookies are not.
- **Disable Vue DevTools in production** — set `app.config.devtools = false` or rely on the automatic disablement in production mode.
- **Clear sensitive state on logout** — call `store.$reset()` (Pinia) or `store.replaceState({})` (Vuex) and invalidate the session server-side.
- **Never put sensitive state in a persisted plugin** (`pinia-plugin-persistedstate`) without explicit field exclusions — persisted state is written to `localStorage`/`sessionStorage` in plaintext.

```typescript
// ❌ INSECURE — raw token and PII in Pinia state
export const useAuthStore = defineStore('auth', {
  state: () => ({
    accessToken: '',     // XSS-readable
    password: '',        // never store
    ssn: '',             // never store
  }),
});

// ✅ SECURE — minimal state, token in HttpOnly cookie (server sets it)
export const useAuthStore = defineStore('auth', {
  state: () => ({
    userId: null as string | null,
    email: '',             // OK for display
    role: 'guest' as string,
    // No token — stored in HttpOnly cookie by the server
  }),
  actions: {
    logout() {
      this.$reset();
      // POST to /api/auth/logout to clear the HttpOnly cookie
    },
  },
});

// ✅ SECURE — pinia-plugin-persistedstate with field exclusion
persistedState({
  paths: ['userId', 'role'], // only non-sensitive fields
  // exclude: ['accessToken', 'ssn']
})
```

---

## 5. `VITE_*` / `VUE_APP_*` Environment Variable Leaks

**Vulnerability:** Any environment variable prefixed `VITE_` (Vite) or `VUE_APP_` (Vue CLI / webpack) is statically inlined into the client bundle and delivered to every browser. Secrets placed in these variables — API keys, database passwords, private tokens — become public. The bundle is inspectable via browser DevTools, `strings`, or decompilation tools.

**References:** CWE-312, CWE-215, OWASP A02:2025

### Mandatory Rules

- **Never prefix server secrets with `VITE_` or `VUE_APP_`** — these prefixes signal "this is public"; use them only for genuinely public configuration values.
- **Move all secret values to server-side environment variables** accessed only in Nuxt server routes (`server/`), Express/Nitro middleware, or SSR-only code paths.
- **In Nuxt, use `useRuntimeConfig()` correctly** — `runtimeConfig.public.*` is exposed to the client; `runtimeConfig.*` (non-public) is server-only. Never place secrets under `public`.
- **Audit `.env` files** — run `grep -r 'VITE_\|VUE_APP_' .env*` to confirm no secrets exist under these prefixes.
- **Add `.env*` to `.gitignore`** — never commit `.env.local`, `.env.production`, or any file containing real credentials.

```bash
# ❌ INSECURE — all three values become public in the bundle
VITE_STRIPE_SECRET_KEY=sk_live_abc123
VITE_DATABASE_URL=postgresql://prod:password@db/app
VUE_APP_JWT_SECRET=supersecret

# ✅ SECURE — only public config uses the VITE_ prefix
VITE_APP_TITLE="My App"
VITE_API_BASE_URL="https://api.example.com"

# Server-only secrets (never prefixed VITE_ or VUE_APP_)
STRIPE_SECRET_KEY=sk_live_abc123
DATABASE_URL=postgresql://prod:password@db/app
```

```typescript
// ✅ SECURE — Nuxt: runtimeConfig with correct separation
// nuxt.config.ts
export default defineNuxtConfig({
  runtimeConfig: {
    stripeSecretKey: '',       // server-only (process.env.STRIPE_SECRET_KEY)
    databaseUrl: '',           // server-only
    public: {
      apiBase: '',             // exposed to client (NUXT_PUBLIC_API_BASE)
      appTitle: 'My App',      // exposed to client
    },
  },
});

// server/api/checkout.post.ts
export default defineEventHandler(async (event) => {
  const config = useRuntimeConfig();
  // config.stripeSecretKey — server-only ✅
  // config.public.apiBase  — available everywhere ✅
});
```

---

## 6. Vue Router Open Redirect

**Vulnerability:** `router.push(route.query.redirect)` or `router.replace(userInput)` with user-controlled strings allows attackers to redirect users to malicious external sites after login, enabling phishing attacks. Vue Router accepts absolute URLs like `https://evil.com` as redirect targets.

**References:** CWE-601, OWASP A01:2025

### Mandatory Rules

- **Always validate redirect targets against an allowlist of internal paths** before calling `router.push()` with user-supplied values.
- **Only allow relative paths (starting with `/`)** for redirect parameters — reject any value containing `://` or starting with `//`.
- **Validate `next` / `redirect` / `returnTo` query parameters server-side in Nuxt middleware** — not just in client-side route guards.
- **Never redirect to an arbitrary URL from the login success handler** without validation.

```typescript
// ❌ INSECURE — open redirect after login
const redirect = route.query.redirect as string;
await router.push(redirect); // attacker sends ?redirect=https://evil.com

// ✅ SECURE — safeRedirect helper
function safeRedirect(target: string | undefined, fallback = '/'): string {
  if (!target) return fallback;
  // Allow only relative paths (no protocol, no //hostname)
  if (target.startsWith('/') && !target.startsWith('//')) {
    // Additional: block encoded sequences like /%2F
    try {
      const decoded = decodeURIComponent(target);
      if (decoded.startsWith('//') || decoded.includes('://')) return fallback;
    } catch {
      return fallback;
    }
    return target;
  }
  return fallback;
}

// After login:
const redirect = safeRedirect(route.query.redirect as string);
await router.push(redirect);
```

---

## 7. Route Guard Authorization — Client-Side Only Bypass

**Vulnerability:** Vue Router `beforeEach` guards enforce access control in the browser but are trivially bypassed: an attacker can delete the guard via browser console, use the history API directly, or access the API endpoints backing the protected pages directly. Route guards are UX features, not security controls.

**References:** CWE-284, CWE-602, OWASP A01:2025

### Mandatory Rules

- **Enforce all authorization server-side** — every API call behind a route guard must also validate the session/token server-side and return 401/403 if unauthorized.
- **In Nuxt, use server-side middleware** (`server/middleware/`) for authentication checks on SSR-rendered pages — do not rely on `defineNuxtRouteMiddleware` alone.
- **Never hide sensitive data in the component's JavaScript bundle** assuming the guard will prevent access — if the data is bundled, it's accessible regardless of guards.
- **Treat route guards as UX only** — they prevent accidental navigation, not intentional bypass.

```typescript
// ❌ INSECURE — authorization enforced only in client guard
router.beforeEach((to) => {
  if (to.meta.requiresAuth && !authStore.isLoggedIn) {
    return '/login';
  }
  // API still returns data to unauthenticated callers! ❌
});

// ✅ SECURE — guard for UX + server enforces authz on every API call
// Client: route guard for UX redirect
router.beforeEach((to) => {
  if (to.meta.requiresAuth && !authStore.isLoggedIn) {
    return { path: '/login', query: { redirect: to.fullPath } };
  }
});

// Server: Nuxt server route enforces authorization independently
// server/api/admin/users.get.ts
export default defineEventHandler(async (event) => {
  const session = await requireUserSession(event); // throws 401 if not authed
  requireRole(session.user, 'admin');               // throws 403 if not admin
  return await db.users.findAll();
});
```

---

## 8. Nuxt SSR State Transfer XSS — `useState` / Payload Hydration

**Vulnerability:** Nuxt serializes server-side state into a `<script>` tag in the HTML payload for client-side hydration. If user-supplied data containing `</script>` or HTML-breaking sequences is embedded in this payload without proper encoding, it creates an XSS vector. This is analogous to Next.js's `__NEXT_DATA__` injection risk.

**References:** CWE-79, OWASP A03:2025, CVE-2023-3224

### Mandatory Rules

- **Never embed user-controlled data in Nuxt `useState()` without sanitization** — the state payload is serialized directly into the HTML document.
- **Use `devalue` serialization correctly** — Nuxt uses `devalue` which handles `</script>` escaping, but ensure you use the built-in Nuxt data fetching (`useFetch`, `useAsyncData`) rather than manual `<script>` injection.
- **Validate and sanitize all data fetched server-side** before placing it in state that will be hydrated client-side.
- **Never use `dangerouslySetInnerHTML`-equivalent patterns** in Nuxt templates — `v-html` on hydrated server state is double-dangerous.
- **Keep the Nuxt version up to date** — CVE-2023-3224 (Critical 9.8, Nuxt < 3.4.0) allowed path traversal via `_nuxt/` URL manipulation.

```typescript
// ❌ INSECURE — user content in useState that reaches v-html
const post = useState('post', () => ({
  title: route.query.title,  // user-controlled, goes into HTML payload
  body: route.query.body,    // user-controlled
}));
// In template: <div v-html="post.body" />  ← XSS via payload + v-html

// ✅ SECURE — sanitize before storing in state, use text interpolation
import DOMPurify from 'isomorphic-dompurify';

const { data: post } = await useFetch(`/api/posts/${postId}`);
const safeBody = computed(() =>
  post.value ? DOMPurify.sanitize(post.value.body) : ''
);
// In template: <div v-html="safeBody" />  — sanitized ✅
// Better:      <p>{{ post?.summary }}</p> — no v-html needed ✅
```

---

## 9. Nuxt Server Routes — Authentication and Rate Limiting

**Vulnerability:** Nuxt 3 server routes (`server/api/`, `server/routes/`) are Node.js API endpoints. Without explicit authentication checks, they are publicly accessible. Missing rate limiting enables credential stuffing, brute force, and DoS.

**References:** CWE-284, CWE-307, OWASP A01:2025, OWASP A07:2025

### Mandatory Rules

- **Add authentication middleware to every non-public server route** — use `requireUserSession()` (Nuxt Auth Utils) or validate the session token in a `defineEventHandler`.
- **Implement rate limiting** on authentication endpoints, password reset, and any destructive operation using `nuxt-security` or a middleware like `@nuxtjs/rate-limiter`.
- **Return only required fields** — never serialize full ORM/database model objects; explicitly pick the fields the response needs.
- **Validate all request bodies** with a schema validator (Zod, valibot) before processing.
- **Set HTTP security headers** via the `nuxt-security` module — `X-Content-Type-Options`, `X-Frame-Options`, `Strict-Transport-Security`, `Content-Security-Policy`.

```typescript
// ❌ INSECURE — no authentication, no validation, returns full DB object
export default defineEventHandler(async (event) => {
  const body = await readBody(event);
  const user = await db.user.findFirst({ where: { email: body.email } });
  return user; // leaks passwordHash, internalFlags, etc.
});

// ✅ SECURE — authenticated, validated, field-projected
import { z } from 'zod';

const UpdateSchema = z.object({
  displayName: z.string().min(1).max(100),
  bio: z.string().max(500).optional(),
});

export default defineEventHandler(async (event) => {
  // 1. Authenticate
  const session = await requireUserSession(event);

  // 2. Validate input
  const body = await readValidatedBody(event, UpdateSchema.parse);

  // 3. Update (user owns the resource — IDOR check)
  const updated = await db.user.update({
    where: { id: session.user.id },
    data: body,
    select: { id: true, displayName: true, bio: true }, // explicit projection
  });

  return updated;
});
```

---

## 10. `useFetch` / `$fetch` SSRF in Nuxt Server Routes

**Vulnerability:** When `useFetch` or `$fetch` inside a Nuxt server route makes an HTTP request to a URL derived from user input, it can be used for SSRF — reaching internal services (metadata endpoints, databases, Redis) not reachable from the internet. Nuxt server code runs in a Node.js environment with access to internal network resources.

**References:** CWE-918, OWASP A10:2025

### Mandatory Rules

- **Never construct a `$fetch` / `ofetch` / `fetch` URL from user-supplied input without validation** in server routes.
- **Validate URLs against an allowlist of permitted external domains** before making outbound HTTP requests.
- **Block requests to private IP ranges and cloud metadata endpoints** (`169.254.169.254`, `::1`, `10.0.0.0/8`, `192.168.0.0/16`, `172.16.0.0/12`).
- **Use a URL allowlist or a dedicated HTTP proxy** for all outbound calls from server routes.
- **Resolve hostnames and check the resolved IP** against the private range blocklist to prevent DNS rebinding.

```typescript
// ❌ INSECURE — SSRF: user controls the URL fetched server-side
export default defineEventHandler(async (event) => {
  const { url } = getQuery(event);
  const data = await $fetch(url as string); // SSRF ❌
  return data;
});

// ✅ SECURE — allowlist of permitted API base URLs
const ALLOWED_APIS = new Set([
  'https://api.stripe.com',
  'https://api.github.com',
]);

function assertSafeUrl(rawUrl: string): URL {
  const parsed = new URL(rawUrl); // throws if invalid
  if (!['https:'].includes(parsed.protocol)) {
    throw createError({ statusCode: 400, message: 'Invalid URL protocol' });
  }
  const origin = `${parsed.protocol}//${parsed.host}`;
  if (!ALLOWED_APIS.has(origin)) {
    throw createError({ statusCode: 400, message: 'URL not in allowlist' });
  }
  return parsed;
}

export default defineEventHandler(async (event) => {
  const { endpoint } = getQuery(event);
  const safeUrl = assertSafeUrl(endpoint as string);
  const data = await $fetch(safeUrl.href, {
    headers: { Authorization: `Bearer ${process.env.API_SECRET}` },
  });
  return data;
});
```

---

## 11. Prototype Pollution via Reactive Object Merging

**Vulnerability:** Vue 3's reactivity system uses Proxies, but helper patterns like `Object.assign(reactive({}), userInput)` or deep merge utilities applied to reactive objects can introduce prototype pollution when `userInput` contains `__proto__`, `constructor`, or `prototype` keys. This can corrupt Vue internals or the application's business logic.

**References:** CWE-1321, OWASP A03:2025, CVE-2024-4067 (micromatch), CVE-2024-21490

### Mandatory Rules

- **Never merge untrusted objects directly into reactive state** using `Object.assign` or spread without sanitizing prototype-poisoning keys.
- **Use `JSON.parse(JSON.stringify(obj))` for deep cloning** untrusted data before merging into reactive state — this strips prototype chain pollution.
- **Avoid deep merge utilities** (lodash `merge`, `deepmerge`) with user-supplied objects unless the library explicitly protects against prototype pollution.
- **Validate input schemas with Zod or valibot** which produce plain, sanitized objects with known shapes — never operate on raw user objects.
- **Keep lodash at ≥ 4.17.21** — earlier versions have unfixed prototype pollution CVEs.

```typescript
// ❌ INSECURE — prototype pollution via reactive merge
const settings = reactive({});
const userPrefs = JSON.parse(apiResponse); // { "__proto__": { "admin": true } }
Object.assign(settings, userPrefs); // pollutes Object.prototype ❌

// ❌ INSECURE — deep merge with user data
import merge from 'lodash/merge';
merge(appConfig, userInput); // prototype pollution if userInput is crafted

// ✅ SECURE — parse and validate with Zod first
import { z } from 'zod';
const PrefsSchema = z.object({
  theme: z.enum(['light', 'dark']),
  language: z.string().max(10),
  notifications: z.boolean(),
});
const userPrefs = PrefsSchema.parse(apiResponse); // throws if invalid/extra keys
Object.assign(settings, userPrefs); // safe: Zod output is a plain typed object

// ✅ SECURE — structuredClone removes prototype chain
const safeClone = structuredClone(userPrefs);
Object.assign(settings, safeClone);
```

---

## 12. ReDoS in Custom Validators and Watchers

**Vulnerability:** Vue component validators and Pinia action logic that apply regex patterns to user input can be exploited for Regular Expression Denial of Service (ReDoS) if the pattern has exponential backtracking. This causes the JavaScript event loop to block, freezing the entire browser tab or crashing the SSR server thread.

**References:** CWE-1333, OWASP A06:2025

### Mandatory Rules

- **Avoid nested quantifiers and alternation with overlap** in regex patterns — patterns like `(a+)+`, `(a|aa)+`, or `([a-zA-Z]+)*` cause catastrophic backtracking.
- **Limit input length before applying regex** — cap strings at a maximum length and reject them early if they exceed it.
- **Use simple string operations instead of regex** where possible (`.startsWith()`, `.includes()`, `.split()`) for common validation cases.
- **Test custom regex patterns with ReDoS detectors** — use `safe-regex2` or `redos-detector` in CI.
- **In Nuxt server routes, apply a request timeout** so that a ReDoS in a validator cannot hold the server indefinitely.

```typescript
// ❌ INSECURE — catastrophic backtracking: input like 'aaaaaaaaab' hangs
const emailRegex = /^([a-zA-Z0-9]+\.?)*@([a-zA-Z0-9]+\.?)*\.[a-zA-Z]{2,}$/;
const isValid = emailRegex.test(userEmail); // may block event loop

// ✅ SECURE — bounded, linear-complexity pattern + length check
function validateEmail(email: string): boolean {
  if (email.length > 254) return false; // RFC 5321 max length
  // Simple pattern without nested quantifiers
  const emailRegex = /^[a-zA-Z0-9.!#$%&'*+/=?^_`{|}~-]+@[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*\.[a-zA-Z]{2,}$/;
  return emailRegex.test(email);
}

// ✅ SECURE — use a well-audited library
import { isEmail } from 'validator';
if (!isEmail(userEmail)) throw new Error('Invalid email');
```

---

## 13. Component Prop Validation — Server-Side Enforcement

**Vulnerability:** Vue's `defineProps` type system and runtime validators enforce types and formats only in development mode with a warning — they are stripped in production builds and do not throw. Relying on prop validation for security means no validation in production.

**References:** CWE-20, OWASP A03:2025

### Mandatory Rules

- **Validate all security-relevant data server-side** using Zod, valibot, or a dedicated validation library — never rely on Vue prop types as the primary security control.
- **Use typed props with `defineProps<T>()`** for development-time type safety, but independently validate the underlying API response.
- **Sanitize or reject unexpected values before passing them as props** — especially for props used in `v-html`, `:href`, or `:src` bindings.

```vue
<!-- ❌ INSECURE — prop validator only runs in dev, not a security boundary -->
<script setup>
const props = defineProps({
  url: {
    type: String,
    validator: (v) => v.startsWith('https://'), // dev-only warning ❌
  },
});
</script>
<a :href="props.url">Link</a>

<!-- ✅ SECURE — validate/sanitize before passing the prop -->
<script setup>
const props = defineProps<{ url: string }>();
const safeLink = computed(() => {
  try {
    const parsed = new URL(props.url);
    return parsed.protocol === 'https:' ? props.url : null;
  } catch {
    return null;
  }
});
</script>
<a v-if="safeLink" :href="safeLink">Link</a>
```

---

## 14. CSS Injection via `:style` Binding

**Vulnerability:** `:style="userObject"` or `:style="{ cssProperty: userValue }"` with user-controlled values can inject CSS expressions in older browsers, exfiltrate data via CSS selectors, or cause UI redressing (clickjacking-like attacks via `position: fixed`). In IE11 and legacy Edge, CSS `expression()` was a code execution vector.

**References:** CWE-79, OWASP A03:2025

### Mandatory Rules

- **Never pass user-controlled objects directly to `:style`** — validate or allowlist each CSS property and value.
- **Restrict dynamic style values to a known set of safe properties and patterns** — e.g., color values must match `/^#[0-9a-fA-F]{3,6}$/` or named colors from an allowlist.
- **Avoid user-controlled values for layout properties** (`position`, `z-index`, `overflow`) that could be used for UI redressing.
- **Prefer CSS classes with `:class` binding** for theming rather than inline style injection.

```vue
<!-- ❌ INSECURE — arbitrary CSS from user input -->
<div :style="userTheme"></div>
<div :style="{ color: userInput }"></div>

<!-- ✅ SECURE — allowlisted color values only -->
<script setup>
const SAFE_COLORS = new Set(['red', 'blue', 'green', 'black', 'white']);
const safeColor = computed(() => {
  const c = userTheme.value?.primaryColor ?? '';
  // Allow hex colors or whitelisted names
  if (/^#[0-9a-fA-F]{3,6}$/.test(c) || SAFE_COLORS.has(c)) return c;
  return '#000000'; // default
});
</script>
<div :style="{ color: safeColor }"></div>

<!-- ✅ SECURE — prefer dynamic classes -->
<div :class="`theme-${safeThemeName}`"></div>
```

---

## 15. Supply Chain — Dependency Auditing and Vite Security

**Vulnerability:** Vue projects typically depend on hundreds of npm packages. A compromised or vulnerable transitive dependency (e.g., via dependency confusion or a CVE) can inject malicious code into the client bundle. Vite itself has had path traversal CVEs in its development server.

**References:** CWE-1395, OWASP A06:2025, CVE-2025-30208, CVE-2024-23331, CVE-2024-31224

### Mandatory Rules

- **Run `npm audit --audit-level=high` in CI** and fail the build on high/critical vulnerabilities.
- **Pin dependency versions in `package.json`** (use exact versions or ranges with `~`) and commit `package-lock.json` or `pnpm-lock.yaml`.
- **Never expose the Vite development server to the network** — bind only to `localhost` (the default). If you must expose it, upgrade to Vite ≥ 6.2.3 (CVE-2025-30208 path traversal fix).
- **Restrict Vite's `server.fs.allow`** in `vite.config.ts` to prevent path traversal attacks on the dev server.
- **Use `vite-plugin-checker`** for TypeScript and ESLint integration and `vite-plugin-csp`** for CSP header injection at build time.
- **Audit `vue-i18n` messages for XSS** — CVE-2024-6783: crafted locale messages with embedded HTML in `vue-i18n < 9.13.1` could bypass sanitization.

```typescript
// ✅ SECURE — vite.config.ts hardened
import { defineConfig } from 'vite';

export default defineConfig({
  server: {
    host: 'localhost',    // never '0.0.0.0' in dev
    fs: {
      allow: ['..'],      // restrict to project root and parent only
      deny: ['.env', '.env.*', '*.pem', '*.key', 'node_modules/.cache'],
    },
  },
  build: {
    sourcemap: false,     // disable in production (or use 'hidden')
    rollupOptions: {
      output: {
        // No predictable chunk filenames that reveal internal structure
        chunkFileNames: 'assets/[hash].js',
      },
    },
  },
});
```

```bash
# CI pipeline — fail on high/critical vulnerabilities
npm audit --audit-level=high

# Check for known vulnerabilities including transitive deps
npx better-npm-audit audit --level high

# Check vue-i18n version
npm list vue-i18n  # ensure >= 9.13.1
```

---

## 16. Content Security Policy (CSP) with Vue and Vite

**Vulnerability:** Vue's runtime template compiler requires `unsafe-eval` in CSP, which undermines XSS protection. Without CSP, any XSS vulnerability has full impact. Vite injects inline scripts and styles during development that conflict with strict CSP.

**References:** CWE-79, OWASP A05:2025

### Mandatory Rules

- **Use the Vue pre-compiled build** (the default in Vite production builds) — it does not require `unsafe-eval` in CSP.
- **Never use the Vue full build** (`vue.esm-bundler.js`) in a production app with strict CSP — the runtime compiler requires `unsafe-eval`.
- **Implement nonce-based CSP** using `vite-plugin-csp` or the `nuxt-security` module — inject nonces into all inline scripts.
- **Set the following minimum CSP directives** for a Vue SPA: `default-src 'self'; script-src 'self'; style-src 'self' 'nonce-{nonce}'; img-src 'self' data:; connect-src 'self' https://api.example.com`.
- **In Nuxt, configure security headers** via the `nuxt-security` module which handles nonce injection automatically.
- **Enable `Trusted Types`** in CSP alongside a custom TrustedTypes policy that wraps DOMPurify for `v-html` usage.

```typescript
// ✅ SECURE — nuxt.config.ts with nuxt-security CSP
export default defineNuxtConfig({
  modules: ['nuxt-security'],
  security: {
    headers: {
      contentSecurityPolicy: {
        'default-src': ["'self'"],
        'script-src': ["'self'", "'nonce-{{nonce}}'"],
        'style-src': ["'self'", "'nonce-{{nonce}}'"],
        'img-src': ["'self'", 'data:', 'https:'],
        'connect-src': ["'self'", 'https://api.example.com'],
        'font-src': ["'self'"],
        'frame-ancestors': ["'none'"],
        'form-action': ["'self'"],
        'base-uri': ["'self'"],
      },
      xFrameOptions: 'DENY',
      xContentTypeOptions: 'nosniff',
      strictTransportSecurity: {
        maxAge: 31536000,
        includeSubdomains: true,
      },
      referrerPolicy: 'strict-origin-when-cross-origin',
    },
    rateLimiter: {
      tokensPerInterval: 100,
      interval: 'minute',
    },
  },
});
```

---

## 17. Production Build Hardening

**Vulnerability:** Development-mode Vue apps expose Vue DevTools, verbose error messages (including stack traces and component names), source maps, and the reactive object graph. These aid attackers in reverse-engineering business logic and identifying vulnerabilities.

**References:** CWE-209, CWE-215, OWASP A05:2025

### Mandatory Rules

- **Always build with `NODE_ENV=production`** — Vue 3 automatically disables DevTools, warning messages, and component name exposure in production mode.
- **Set `app.config.performance = false`** in production — performance markers can expose component timing information.
- **Disable source maps in production** or use `'hidden'` source maps uploaded only to an error tracking service (Sentry) — `sourcemap: true` in `vite.config.ts` exposes original source code.
- **Avoid global error handlers that expose stack traces** to the user — log internally, return generic messages.
- **Remove all `console.log` / `console.debug` calls** from production builds using Vite's `drop` option or `vite-plugin-remove-console`.

```typescript
// vite.config.ts — production hardening
export default defineConfig(({ mode }) => ({
  build: {
    sourcemap: mode === 'production' ? false : true,
    minify: 'terser',
    terserOptions: {
      compress: {
        drop_console: true,    // remove all console.* calls
        drop_debugger: true,   // remove debugger statements
      },
    },
  },
}));

// main.ts — production guards
const app = createApp(App);
if (import.meta.env.PROD) {
  app.config.devtools = false;
  app.config.performance = false;
  app.config.warnHandler = () => {}; // suppress Vue warnings in prod
  app.config.errorHandler = (err, _instance, info) => {
    // Log to Sentry/monitoring — never expose to user
    console.error('Application error:', err, info);
  };
}
```

---

## CVE Reference Table

| CVE | Severity | Component | Description | Fixed In |
|-----|----------|-----------|-------------|----------|
| CVE-2025-30208 | High (7.4) | Vite < 6.2.3 / 5.4.15 / 4.5.10 | Path traversal in dev server via URL query string allows reading arbitrary files | Vite 6.2.3, 5.4.15, 4.5.10 |
| CVE-2024-23331 | High (7.4) | Vite < 5.0.12 / 4.5.2 / 3.2.8 | Dev server SSRF — `server.fs.deny` bypass allows reading system files | Vite 5.0.12, 4.5.2, 3.2.8 |
| CVE-2024-31224 | High (7.5) | Vite < 5.2.10 / 4.5.4 | Path traversal in `@fs/` endpoint exposes arbitrary files on Windows | Vite 5.2.10, 4.5.4 |
| CVE-2024-6783 | Medium (6.5) | vue-i18n < 9.13.1 | XSS via crafted locale message with embedded HTML bypassing sanitization | vue-i18n 9.13.1 |
| CVE-2023-3224 | Critical (9.8) | Nuxt < 3.4.0 | Path traversal in `_nuxt/` URL allows reading arbitrary server files | Nuxt 3.4.0 |
| CVE-2022-26649 | Medium (6.1) | vue-router < 4.1.0 | Open redirect via `redirect` property with external URL | vue-router 4.1.0 |
| CVE-2024-4067 | High (7.5) | micromatch < 4.0.8 | ReDoS via crafted glob pattern (used by Vite internally) | micromatch 4.0.8 |
| CVE-2024-21490 | High (7.5) | angular/core (context) | ReDoS in template parsing — Vue uses similar regex-based template parsing risk class | Angular 17.2.0 |
| CVE-2021-23337 | High (7.2) | lodash < 4.17.21 | Command injection and prototype pollution in `template` and `merge` | lodash 4.17.21 |
| GHSA-3p37-3636-q8wv | High (8.1) | vue-demi < 0.14.6 | Prototype pollution in internal merging utility | vue-demi 0.14.6 |

---

## Security Checklist

### XSS Prevention
- [ ] No `v-html` usage with unsanitized user input
- [ ] `v-html` uses a `v-safe-html` directive backed by DOMPurify or sanitized computed
- [ ] No `:href`/`:src` bindings with user-supplied URLs without protocol validation
- [ ] No `Vue.compile()` or `compileToFunction()` with user input
- [ ] No `<component :is="userString">` without allowlist
- [ ] `{{ }}` text interpolation used in preference to `v-html` for user content

### State and Secrets
- [ ] No sensitive data (tokens, passwords, PII) in Pinia/Vuex state
- [ ] JWTs stored in `HttpOnly` cookies, not in reactive state or `localStorage`
- [ ] No `VITE_`/`VUE_APP_` prefix on secret environment variables
- [ ] Nuxt `runtimeConfig` secrets in non-public section only
- [ ] Vue DevTools disabled in production (`app.config.devtools = false`)
- [ ] Pinia persist plugin excludes sensitive fields

### Authorization
- [ ] Server-side authentication check on every Nuxt server route
- [ ] Vue Router guards treated as UX-only, not security boundaries
- [ ] IDOR prevention: resource ownership verified server-side using session identity
- [ ] Rate limiting on auth endpoints and destructive operations
- [ ] Open redirect prevented: redirect targets validated against relative-path-only allowlist

### Nuxt / SSR
- [ ] `useState()` / payload hydration does not contain unsanitized user content
- [ ] `useFetch()`/`$fetch()` URLs in server routes are validated against allowlist
- [ ] Nuxt version ≥ 3.4.0 (CVE-2023-3224 path traversal)
- [ ] `nuxt-security` module installed and CSP headers configured
- [ ] Nuxt SSR server does not expose internal errors or stack traces

### CSP and Headers
- [ ] CSP configured — no `unsafe-eval` in production (use pre-compiled build)
- [ ] Nonce-based CSP for inline scripts via `nuxt-security` or `vite-plugin-csp`
- [ ] `X-Frame-Options: DENY` and `frame-ancestors: 'none'` set
- [ ] `Strict-Transport-Security` with `includeSubdomains` set
- [ ] `X-Content-Type-Options: nosniff` set
- [ ] `Referrer-Policy: strict-origin-when-cross-origin` set

### Supply Chain
- [ ] `npm audit --audit-level=high` passes in CI
- [ ] Vite version ≥ 6.2.3 / 5.4.15 / 4.5.10 (path traversal CVEs)
- [ ] vue-i18n version ≥ 9.13.1 (CVE-2024-6783 XSS)
- [ ] lodash version ≥ 4.17.21 (prototype pollution)
- [ ] `package-lock.json` / `pnpm-lock.yaml` committed and integrity verified
- [ ] Vite dev server bound to `localhost` only, not `0.0.0.0`

### Build Hardening
- [ ] Production build uses `NODE_ENV=production`
- [ ] Source maps disabled (`sourcemap: false`) or hidden in production
- [ ] `console.log` / `console.debug` removed from production bundle
- [ ] `debugger` statements removed from production bundle
- [ ] `drop_console: true` in Terser config
- [ ] Error handler returns generic messages — no stack traces to users

---

## Tooling

| Tool | Purpose | Command |
|------|---------|---------|
| [npm audit](https://docs.npmjs.com/cli/audit) | Dependency vulnerability scanning | `npm audit --audit-level=high` |
| [Snyk](https://snyk.io) | Continuous dependency and code scanning | `npx snyk test` |
| [ESLint vue plugin](https://eslint.vuejs.org) | Vue template and script linting | `eslint . --ext .vue,.ts` |
| [eslint-plugin-security](https://github.com/eslint-community/eslint-plugin-security) | Security-focused ESLint rules | `npm install -D eslint-plugin-security` |
| [vite-plugin-checker](https://vite-plugin-checker.netlify.app) | TS/ESLint checks in Vite | `npm install -D vite-plugin-checker` |
| [nuxt-security](https://nuxt-security.vercel.app) | Security headers + rate limiting for Nuxt | `npx nuxi module add security` |
| [DOMPurify](https://github.com/cure53/DOMPurify) | HTML sanitization for `v-html` | `npm install dompurify isomorphic-dompurify` |
| [safe-regex2](https://github.com/nicolo-ribaudo/safe-regex) | ReDoS detection for custom regex | `npx safe-regex "your-pattern"` |
| [Semgrep Vue rules](https://semgrep.dev) | Static analysis for Vue patterns | `semgrep --config p/vue` |
| [retire.js](https://retirejs.github.io) | Known vulnerable JS library detection | `npx retire --js --node` |
