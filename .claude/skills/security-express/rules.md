# 🚂 Express.js Security Rules

> **Standard:** Express.js 4.x / 5.x secure development rules covering injection, authentication, CORS, headers, rate limiting, sessions, JWT, CSRF, template engine XSS, file upload, and supply chain security.
> **Sources:** Express.js Security Best Practices, Node.js Security WG, OWASP Top 10:2025, CWE/MITRE, NVD, GitHub Advisory Database, Snyk Node.js Security Advisories
> **Version:** 1.0.0
> **Last updated:** March 2026
> **Scope:** Express.js 4.x and 5.x web applications and APIs, including common middleware (Helmet, express-rate-limit, express-session, jsonwebtoken, multer, EJS/Handlebars/Pug template engines, cors, csurf/csrf-csrf).

---

## General Instructions

Apply these rules when generating, reviewing, or refactoring any Express.js code. Express ships with no security defaults — it requires explicit opt-in for every protection: security headers, rate limiting, CORS policies, session hardening, CSRF protection, and body size limits. The most dangerous Express-specific vulnerability is **middleware order bugs** — placing authentication middleware after route handlers silently bypasses all access control. The second most common critical is **mass assignment via `req.body`** saved directly to ORM models, enabling privilege escalation. All input must be validated server-side; no client-side validation is a security boundary.

---

## 1. Middleware Order — Authentication and Authorization Bypass

**Vulnerability:** Express processes middleware in the exact registration order. A route registered before the authentication middleware is publicly accessible, regardless of intent. This is the most common architecture mistake in Express apps — protecting `app.use('/api', authMiddleware)` after defining `app.get('/api/admin', handler)` means the admin route was already matched and served without authentication.

**References:** CWE-284, CWE-863, OWASP A01:2025

### Mandatory Rules

- **Register security middleware (auth, rate limiting, input validation) BEFORE route handlers** — the order of `app.use()` and `app.get/post/put/delete()` calls determines what executes first.
- **Place `express.json()`, `express.urlencoded()`, and `helmet()` at the top** of the middleware stack, before any route definitions.
- **Never register routes above their protecting middleware** — audit the file top-to-bottom; every route must come after its guard.
- **Authenticate at the router level**, not just in individual handlers — use `router.use(authenticate)` before all protected routes.
- **Use `app.use('*', notFoundHandler)` as the last registered middleware** to prevent route fallthrough leaks.

```javascript
// ❌ INSECURE — route registered before auth middleware
app.get('/api/admin/users', adminHandler); // publicly accessible ❌
app.use('/api/admin', requireAdmin);       // never runs for the route above

// ✅ SECURE — middleware registered before routes
const adminRouter = express.Router();
adminRouter.use(authenticate);   // runs first for all routes below
adminRouter.use(requireAdmin);   // runs second
adminRouter.get('/users', adminHandler);   // auth enforced ✅
app.use('/api/admin', adminRouter);

// ✅ SECURE — top of app.js: global middleware first, then routes
app.use(helmet());
app.use(express.json({ limit: '10kb' }));
app.use(express.urlencoded({ extended: false, limit: '10kb' }));
app.use(cookieParser());
// ... other global middleware
app.use('/api/public', publicRouter);
app.use('/api', authenticate);    // all routes below require auth
app.use('/api/users', userRouter);
app.use('/api/admin', requireAdmin, adminRouter);
app.use('*', notFoundHandler);    // catch-all last
```

---

## 2. SQL Injection — Parameterized Queries

**Vulnerability:** Express applications using raw SQL drivers (`pg`, `mysql2`, `sqlite3`, `better-sqlite3`) without parameterized queries are trivially exploited for SQL injection. String interpolation or concatenation with `req.body`, `req.params`, or `req.query` is the most common pattern.

**References:** CWE-89, OWASP A03:2025

### Mandatory Rules

- **Always use parameterized queries** (`$1`, `?`, or named bindings) — never concatenate or interpolate request values into SQL strings.
- **Use an ORM with query builder** (Prisma, Sequelize, TypeORM, Drizzle) for all business logic — call raw SQL only when absolutely necessary, and use the ORM's raw query parameterization.
- **Validate and sanitize `req.params.id`** before using as a database identifier — verify it matches the expected format (`/^\d+$/` for integer IDs).
- **Restrict database user permissions** — the application DB user should not have `DROP`, `CREATE`, or admin privileges.

```javascript
// ❌ INSECURE — SQL injection via string interpolation
app.get('/users/:id', async (req, res) => {
  const result = await db.query(
    `SELECT * FROM users WHERE id = ${req.params.id}` // injection ❌
  );
  res.json(result.rows[0]);
});

// ❌ INSECURE — via template literals in Sequelize raw query
const users = await sequelize.query(
  `SELECT * FROM users WHERE name = '${req.query.name}'`
);

// ✅ SECURE — parameterized query (pg)
app.get('/users/:id', async (req, res) => {
  const id = parseInt(req.params.id, 10);
  if (isNaN(id) || id <= 0) return res.status(400).json({ error: 'Invalid ID' });
  const result = await db.query('SELECT id, email, role FROM users WHERE id = $1', [id]);
  if (!result.rows[0]) return res.status(404).json({ error: 'Not found' });
  res.json(result.rows[0]);
});

// ✅ SECURE — Prisma ORM (auto-parameterized)
const user = await prisma.user.findUnique({
  where: { id: parseInt(req.params.id, 10) },
  select: { id: true, email: true, role: true }, // explicit projection
});

// ✅ SECURE — Sequelize raw query with replacements
const users = await sequelize.query(
  'SELECT id, name FROM users WHERE name = :name',
  { replacements: { name: req.query.name }, type: QueryTypes.SELECT }
);
```

---

## 3. NoSQL Injection — MongoDB / Mongoose

**Vulnerability:** MongoDB query operators (`$where`, `$gt`, `$regex`, `$ne`) embedded in user-supplied objects allow attackers to bypass authentication, extract arbitrary data, or cause DoS. When `req.body` is passed directly as a MongoDB filter, a crafted body like `{ "password": { "$ne": "" } }` returns documents where the password is not empty — bypassing auth.

**References:** CWE-943, OWASP A03:2025, CVE-2022-25845

### Mandatory Rules

- **Never pass `req.body` directly as a MongoDB/Mongoose query filter** — always extract and validate specific fields.
- **Use `mongo-sanitize` or `express-mongo-sanitize` middleware** to strip `$` and `.` from all request inputs before they reach queries.
- **Avoid `$where` queries** — they execute JavaScript server-side and are equivalent to `eval()`.
- **Use Mongoose schemas with strict mode** (`strict: true` is default) — reject keys not defined in the schema.
- **Validate that ID parameters match MongoDB ObjectId format** before querying.

```javascript
// ❌ INSECURE — NoSQL injection: body { "password": { "$ne": "" } }
app.post('/login', async (req, res) => {
  const user = await User.findOne({ email: req.body.email, password: req.body.password });
  // above returns a user even if password is wrong! ❌
});

// ❌ INSECURE — $where is server-side JS execution
User.find({ $where: `this.username === '${req.query.username}'` });

// ✅ SECURE — extract fields explicitly, hash-compare password
const { email, password } = req.body;
if (typeof email !== 'string' || typeof password !== 'string') {
  return res.status(400).json({ error: 'Invalid input' });
}
const user = await User.findOne({ email: email.toLowerCase() }).select('+passwordHash');
if (!user || !await bcrypt.compare(password, user.passwordHash)) {
  return res.status(401).json({ error: 'Invalid credentials' });
}

// ✅ SECURE — express-mongo-sanitize middleware (strips $ and . from all inputs)
const mongoSanitize = require('express-mongo-sanitize');
app.use(mongoSanitize());
```

---

## 4. Command Injection — `child_process`

**Vulnerability:** `child_process.exec()`, `execSync()`, and `spawn()` with `shell: true` interpret user input as shell commands, enabling arbitrary command execution. Even `spawn()` without `shell: true` can be abused if a shell executable is passed as the command.

**References:** CWE-78, OWASP A03:2025

### Mandatory Rules

- **Never pass user input to `exec()` or `execSync()`** — they run commands through the system shell, interpreting metacharacters like `;`, `|`, `&&`, `$()`, and backticks.
- **Use `spawn(command, argsArray, { shell: false })`** when subprocess execution is unavoidable — pass arguments as an array, never as a concatenated string.
- **Prefer Node.js library alternatives** over shelling out: use `sharp` instead of ImageMagick CLI, `archiver` instead of `zip`, `ffmpeg-static` instead of `ffmpeg` CLI.
- **If shell execution is required**, validate the input against a strict allowlist of permitted values before use.

```javascript
// ❌ INSECURE — command injection via exec
const { exec } = require('child_process');
app.post('/convert', (req, res) => {
  exec(`convert ${req.body.filename} output.pdf`, callback); // ❌
  // attacker sends: filename = "x; rm -rf /"
});

// ❌ INSECURE — spawn with shell: true is equivalent to exec
const { spawn } = require('child_process');
spawn('sh', ['-c', `grep ${req.query.term} /var/log/app.log`], { shell: true }); // ❌

// ✅ SECURE — spawn with shell: false and argument array
const path = require('path');
const { spawn } = require('child_process');

app.post('/convert', (req, res) => {
  const filename = req.body.filename;
  // Validate: only allow alphanumeric filenames with allowed extensions
  if (!/^[\w-]+\.(jpg|jpeg|png|gif)$/.test(filename)) {
    return res.status(400).json({ error: 'Invalid filename' });
  }
  const inputPath = path.resolve('/uploads', filename);
  // No shell interpolation — args are passed as an array
  const proc = spawn('convert', [inputPath, 'output.pdf'], { shell: false });
  proc.on('close', (code) => res.json({ success: code === 0 }));
});

// ✅ SECURE — use Node.js library instead of CLI
const sharp = require('sharp');
await sharp(inputPath).toFormat('webp').toFile(outputPath);
```

---

## 5. Path Traversal — `res.sendFile` and File Operations

**Vulnerability:** Using `res.sendFile()`, `fs.readFile()`, or `fs.createReadStream()` with user-controlled paths allows path traversal attacks (`../../etc/passwd`). Express's `res.sendFile()` does not canonicalize paths by default. `express.static()` misconfiguration can also expose the entire filesystem.

**References:** CWE-22, OWASP A01:2025, CVE-2022-25912

### Mandatory Rules

- **Always resolve the full path and verify it starts with the expected base directory** before any file read or send operation.
- **Use `path.resolve()` then check with `path.startsWith(baseDir)`** — do not use `path.join()` alone, as it normalizes `../` but does not guarantee the result is within the expected directory.
- **Pass an absolute `root` option to `res.sendFile()`** — this restricts the file to within that directory.
- **Never pass `req.params`, `req.query`, or `req.body` directly to `fs` operations** without the prefix check.
- **Configure `express.static()` with `dotfiles: 'deny'`** to prevent serving hidden files like `.env`, `.git`, `.htpasswd`.

```javascript
// ❌ INSECURE — path traversal: ?file=../../etc/passwd
app.get('/download', (req, res) => {
  res.sendFile(req.query.file);           // traversal ❌
  fs.readFile(req.query.file, callback);  // traversal ❌
});

// ✅ SECURE — resolve and verify prefix
const path = require('path');
const UPLOADS_DIR = path.resolve(__dirname, 'uploads');

app.get('/download', (req, res) => {
  const requestedFile = req.query.file;
  if (!requestedFile) return res.status(400).send('Missing file parameter');

  // Canonicalize and verify within base directory
  const fullPath = path.resolve(UPLOADS_DIR, requestedFile);
  if (!fullPath.startsWith(UPLOADS_DIR + path.sep)) {
    return res.status(403).send('Access denied');
  }

  // Safe: root option restricts to UPLOADS_DIR
  res.sendFile(requestedFile, { root: UPLOADS_DIR });
});

// ✅ SECURE — hardened express.static
app.use('/public', express.static(path.join(__dirname, 'public'), {
  dotfiles: 'deny',       // deny .env, .git, etc.
  index: false,           // no directory listing
  etag: false,            // optional: disable ETag for privacy
}));
```

---

## 6. CORS Misconfiguration

**Vulnerability:** Overly permissive CORS configuration (`origin: '*'`, or reflecting `req.headers.origin` unconditionally) allows any website to make cross-origin requests to your API using the visitor's credentials (cookies, `Authorization` header). This enables CSRF, session hijacking, and data exfiltration from authenticated users.

**References:** CWE-942, OWASP A05:2025, CVE-2023-26159

### Mandatory Rules

- **Never use `cors({ origin: '*' })`** on endpoints that accept credentials (`credentials: true`) — the browser blocks `*` with credentials, but the configuration itself is a security signal that access control is not considered.
- **Never reflect `req.headers.origin` unconditionally** as the `Access-Control-Allow-Origin` value — this grants all origins full access.
- **Define an explicit allowlist of permitted origins** and validate the request `Origin` against it.
- **Only enable `credentials: true`** when strictly required, and always pair it with a strict origin allowlist.
- **Restrict allowed methods and headers** to the minimum needed.

```javascript
// ❌ INSECURE — reflects any origin with credentials
app.use(cors({
  origin: (origin, callback) => callback(null, origin), // echoes attacker's origin ❌
  credentials: true,
}));

// ❌ INSECURE — wildcard allows any origin
app.use(cors({ origin: '*' }));

// ✅ SECURE — explicit allowlist
const ALLOWED_ORIGINS = new Set([
  'https://app.example.com',
  'https://admin.example.com',
  process.env.NODE_ENV === 'development' ? 'http://localhost:3000' : null,
].filter(Boolean));

app.use(cors({
  origin: (origin, callback) => {
    // Allow requests with no origin (curl, Postman) or from allowed list
    if (!origin || ALLOWED_ORIGINS.has(origin)) {
      callback(null, true);
    } else {
      callback(new Error(`CORS: Origin ${origin} not allowed`));
    }
  },
  credentials: true,              // only when cookies/auth headers needed
  methods: ['GET', 'POST', 'PUT', 'DELETE'],
  allowedHeaders: ['Content-Type', 'Authorization'],
  maxAge: 86400,                  // cache preflight for 24h
}));
```

---

## 7. Security Headers — Helmet.js

**Vulnerability:** Express sets no security HTTP headers by default. Without `helmet`, responses include `X-Powered-By: Express` (fingerprinting), no `Content-Security-Policy`, no `X-Frame-Options` (clickjacking), no `X-Content-Type-Options` (MIME sniffing), and no `Strict-Transport-Security`. Each missing header represents a class of attacks that remain unmitigated.

**References:** CWE-693, CWE-1021, OWASP A05:2025

### Mandatory Rules

- **Install and enable `helmet` as the first middleware** — `app.use(helmet())` applies 15+ security headers with sensible defaults.
- **Configure a `Content-Security-Policy`** — the default Helmet CSP is strict; customize `scriptSrc`, `styleSrc`, and `imgSrc` to match your application's actual sources.
- **Disable `X-Powered-By`** with `app.disable('x-powered-by')` in addition to Helmet (belt-and-suspenders).
- **Enable `hsts` with `includeSubDomains`** for production — Helmet includes it, but verify `maxAge` is at least 31536000 (one year).

```javascript
// ❌ INSECURE — no security headers
const app = express();
app.use(express.json());
app.use(routes); // serves with default Express headers (no CSP, no HSTS, etc.)

// ✅ SECURE — Helmet with CSP configuration
const helmet = require('helmet');

app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      scriptSrc: ["'self'"],
      styleSrc: ["'self'", "'unsafe-inline'"],    // tighten if possible
      imgSrc: ["'self'", 'data:', 'https:'],
      connectSrc: ["'self'", 'https://api.example.com'],
      fontSrc: ["'self'"],
      frameSrc: ["'none'"],
      objectSrc: ["'none'"],
      upgradeInsecureRequests: [],
    },
  },
  crossOriginEmbedderPolicy: true,
  crossOriginOpenerPolicy: { policy: 'same-origin' },
  crossOriginResourcePolicy: { policy: 'cross-origin' }, // or 'same-site'
  hsts: {
    maxAge: 31536000,
    includeSubDomains: true,
    preload: true,
  },
  referrerPolicy: { policy: 'strict-origin-when-cross-origin' },
}));
app.disable('x-powered-by'); // belt-and-suspenders
```

---

## 8. Rate Limiting — Brute Force and DoS Prevention

**Vulnerability:** Express has no built-in rate limiting. Without it, authentication endpoints, password reset, and any resource-intensive operation are vulnerable to brute force attacks, credential stuffing, and application-layer DoS.

**References:** CWE-307, CWE-770, OWASP A07:2025

### Mandatory Rules

- **Apply rate limiting to all authentication endpoints** (login, register, password reset, OTP verification) — use `express-rate-limit` with a window of ≤ 15 minutes and a low request count (e.g., 10–20 requests).
- **Apply a global rate limit** to all routes as a baseline DoS protection.
- **Use a Redis store** (`rate-limit-redis`) in multi-instance/clustered deployments — the default in-memory store is per-process and easily bypassed by load balancers.
- **Return `429 Too Many Requests`** with a `Retry-After` header — use Helmet's `standardHeaders: true` for this.
- **Beware CVE-2024-29415** — the `ip` package (used internally by `express-rate-limit` < 7.5.0) misclassifies `::ffff:127.0.0.1` as non-loopback; upgrade to `express-rate-limit >= 7.5.0`.

```javascript
// ❌ INSECURE — no rate limiting on login endpoint
app.post('/api/auth/login', loginHandler); // unlimited brute force ❌

// ✅ SECURE — tiered rate limiting
const rateLimit = require('express-rate-limit');
const RedisStore = require('rate-limit-redis');
const { createClient } = require('redis');

const redisClient = createClient({ url: process.env.REDIS_URL });
await redisClient.connect();

// Strict limit for auth endpoints
const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,  // 15 minutes
  max: 20,                    // 20 attempts per window per IP
  standardHeaders: true,      // return Retry-After in RateLimit-* headers
  legacyHeaders: false,
  store: new RedisStore({ sendCommand: (...args) => redisClient.sendCommand(args) }),
  message: { error: 'Too many requests, please try again later.' },
});

// Global baseline limit
const globalLimiter = rateLimit({
  windowMs: 60 * 1000,  // 1 minute
  max: 300,             // 300 req/min global
  standardHeaders: true,
  legacyHeaders: false,
  store: new RedisStore({ sendCommand: (...args) => redisClient.sendCommand(args) }),
});

app.use(globalLimiter);
app.post('/api/auth/login', authLimiter, loginHandler);
app.post('/api/auth/register', authLimiter, registerHandler);
app.post('/api/auth/reset-password', authLimiter, resetPasswordHandler);
```

---

## 9. Session Security — `express-session`

**Vulnerability:** `express-session` with default settings uses an insecure in-memory store (lost on restart), a weak session ID, and cookie settings that expose the session to XSS (`httpOnly: false`) and network interception (`secure: false`). The most common misconfiguration is shipping with `secret: 'keyboard cat'` or another hardcoded string.

**References:** CWE-311, CWE-384, OWASP A07:2025

### Mandatory Rules

- **Use a cryptographically random, long secret** (minimum 32 bytes from `crypto.randomBytes()`) stored in an environment variable — never hardcode it.
- **Set `httpOnly: true`, `secure: true`, `sameSite: 'strict'` (or `'lax'`)** on the session cookie — `httpOnly` prevents XSS access, `secure` prevents transmission over HTTP, `sameSite` mitigates CSRF.
- **Use a persistent session store** (Redis with `connect-redis`, or `connect-pg-simple` for PostgreSQL) — never use the default in-memory store in production.
- **Regenerate the session ID on privilege escalation** (login, password change) — call `req.session.regenerate()` to prevent session fixation.
- **Set a session `maxAge`** and implement idle timeout — sessions should not be eternal.
- **Destroy the session on logout** — call `req.session.destroy()` and clear the cookie.

```javascript
// ❌ INSECURE — weak secret, no secure flags, in-memory store
const session = require('express-session');
app.use(session({
  secret: 'keyboard cat',       // hardcoded ❌
  resave: false,
  saveUninitialized: true,
  // no cookie options — defaults are insecure ❌
}));

// ✅ SECURE — hardened session configuration
const session = require('express-session');
const RedisStore = require('connect-redis').default;
const { createClient } = require('redis');

const redisClient = createClient({ url: process.env.REDIS_URL });
await redisClient.connect();

app.use(session({
  secret: process.env.SESSION_SECRET,   // 64+ char random string from env
  resave: false,
  saveUninitialized: false,             // don't create session until data is set
  rolling: true,                        // reset maxAge on each request (sliding window)
  store: new RedisStore({ client: redisClient }),
  cookie: {
    httpOnly: true,                     // no JS access
    secure: process.env.NODE_ENV === 'production', // HTTPS only in prod
    sameSite: 'strict',                 // CSRF mitigation
    maxAge: 30 * 60 * 1000,           // 30-minute idle timeout
  },
  name: '__Host-sess',                 // '__Host-' prefix enforces secure + no subdomain
}));

// Session regeneration on login (prevent fixation)
app.post('/login', async (req, res) => {
  const user = await authenticateUser(req.body.email, req.body.password);
  if (!user) return res.status(401).json({ error: 'Invalid credentials' });
  req.session.regenerate((err) => {    // new session ID ✅
    if (err) return next(err);
    req.session.userId = user.id;
    req.session.role = user.role;
    res.json({ message: 'Logged in' });
  });
});

// Destroy session on logout
app.post('/logout', (req, res) => {
  req.session.destroy((err) => {
    res.clearCookie('__Host-sess');
    res.json({ message: 'Logged out' });
  });
});
```

---

## 10. JWT Security — `jsonwebtoken`

**Vulnerability:** Common JWT misconfigurations in Express apps include: accepting the `none` algorithm (CVE-2015-9235, CVSS 9.8), not verifying `exp`/`iss`/`aud` claims, hardcoded or weak secrets, storing JWTs in `localStorage` (XSS-accessible), and not implementing token revocation.

**References:** CWE-347, CWE-295, OWASP A07:2025, CVE-2022-23529

### Mandatory Rules

- **Always specify `algorithms` explicitly** in `jwt.verify()` — never use `{ algorithms: ['none'] }` or omit the option (older versions defaulted to accepting `none`).
- **Validate `exp`, `iss`, and `aud` claims** in the verify options — pass `{ issuer, audience }` to `jwt.verify()`.
- **Use secrets of at least 256 bits** for HS256, or RSA-2048/ECDSA P-256 keys for RS256/ES256 — never use a short or predictable string.
- **Store JWTs in `HttpOnly` cookies**, not in `localStorage` — XSS can steal `localStorage` tokens trivially.
- **Keep access token TTL short** (15 minutes) and use a separate long-lived refresh token with revocation support.
- **Upgrade `jsonwebtoken` to ≥ 9.0.0** (CVE-2022-23529 — arbitrary file read via crafted keys in version < 9.0.0).

```javascript
// ❌ INSECURE — algorithm not specified, no claims validation, weak secret
const jwt = require('jsonwebtoken');
const SECRET = 'secret'; // too short ❌

app.get('/profile', (req, res) => {
  const token = req.headers.authorization?.split(' ')[1];
  const decoded = jwt.verify(token, SECRET); // accepts 'none' algorithm ❌
  // no exp/iss/aud validation ❌
  res.json(decoded);
});

// ✅ SECURE — algorithm pinned, claims validated, strong secret
const jwt = require('jsonwebtoken');
const { promisify } = require('util');
const jwtVerify = promisify(jwt.verify);

const JWT_ACCESS_SECRET = process.env.JWT_ACCESS_SECRET; // 64-char random hex
const JWT_ISSUER = 'https://api.example.com';
const JWT_AUDIENCE = 'https://app.example.com';

// Middleware
async function authenticate(req, res, next) {
  try {
    const authHeader = req.headers.authorization;
    if (!authHeader?.startsWith('Bearer ')) {
      return res.status(401).json({ error: 'Missing token' });
    }
    const token = authHeader.slice(7);
    const decoded = await jwtVerify(token, JWT_ACCESS_SECRET, {
      algorithms: ['HS256'],       // pin algorithm — never allow 'none'
      issuer: JWT_ISSUER,
      audience: JWT_AUDIENCE,
      // exp is automatically verified by jsonwebtoken
    });
    req.user = { id: decoded.sub, role: decoded.role };
    next();
  } catch (err) {
    return res.status(401).json({ error: 'Invalid or expired token' });
  }
}

// Issue tokens with short TTL
function issueAccessToken(userId, role) {
  return jwt.sign(
    { sub: userId, role },
    JWT_ACCESS_SECRET,
    { algorithm: 'HS256', expiresIn: '15m', issuer: JWT_ISSUER, audience: JWT_AUDIENCE }
  );
}
```

---

## 11. CSRF Protection

**Vulnerability:** APIs that use cookie-based authentication (sessions or JWT in `HttpOnly` cookies) are vulnerable to Cross-Site Request Forgery if CSRF tokens are not enforced. An attacker's page can trigger state-changing requests using the victim's browser cookies.

**References:** CWE-352, OWASP A01:2025

### Mandatory Rules

- **Use `csrf-csrf` (the maintained successor to deprecated `csurf`)** for CSRF protection on session-authenticated apps.
- **Double-submit cookie pattern or synchronizer token pattern** — send a CSRF token in the response and require it in the request header or body.
- **Verify `SameSite=Strict` on session cookies** — this provides CSRF protection without a token for most cases, but should not be the sole protection for high-value operations.
- **For stateless JWT-in-header APIs**, CSRF is not applicable because the browser does not automatically send `Authorization: Bearer` headers across origins.
- **Validate the `Origin` or `Referer` header** as a defense-in-depth measure on state-changing endpoints.

```javascript
// ✅ SECURE — CSRF protection with csrf-csrf
const { doubleCsrf } = require('csrf-csrf');

const {
  generateToken,
  doubleCsrfProtection,
} = doubleCsrf({
  getSecret: () => process.env.CSRF_SECRET,
  cookieName: '__Host-csrf',
  cookieOptions: {
    sameSite: 'strict',
    httpOnly: true,
    secure: process.env.NODE_ENV === 'production',
  },
  size: 64,             // token size in bytes
  ignoredMethods: new Set(['GET', 'HEAD', 'OPTIONS']),
});

// Provide CSRF token to client
app.get('/api/csrf-token', (req, res) => {
  res.json({ csrfToken: generateToken(req, res) });
});

// Apply CSRF protection to all state-changing routes
app.use(doubleCsrfProtection);
// All POST/PUT/DELETE routes below are now CSRF-protected
app.post('/api/orders', authenticate, createOrderHandler);
app.delete('/api/account', authenticate, deleteAccountHandler);
```

---

## 12. Template Engine XSS — EJS / Handlebars / Pug

**Vulnerability:** Each Express template engine has both safe and unsafe output tags. Using the unsafe variant with user input results in XSS. The dangerous patterns differ by engine: EJS uses `<%-`, Handlebars uses `{{{`, and Pug uses `!= ` — all inject raw HTML without escaping.

**References:** CWE-79, OWASP A03:2025

### Mandatory Rules

- **Always use auto-escaped output by default** — EJS `<%= %>`, Handlebars `{{ }}`, Pug `= `.
- **Never use raw output directives** (`<%- %>`, `{{{ }}}`, `!= `) with user-controlled data.
- **Sanitize with DOMPurify or a server-side sanitizer** before rendering if you must render rich HTML content.
- **Set `res.setHeader('X-Content-Type-Options', 'nosniff')`** and a strict CSP to limit XSS impact even if a template injection occurs.
- **Audit all template files** for raw output tags (`<%- `, `{{{`, `!= `) and verify each is intentional and sanitized.

```html
<!-- EJS -->
<!-- ❌ INSECURE — raw HTML output, attacker controls userBio -->
<div><%- userBio %></div>

<!-- ✅ SECURE — auto-escaped output -->
<div><%= userBio %></div>

<!-- ✅ SECURE — sanitized before rendering if HTML is needed -->
<div><%- sanitizedBio %></div>  <!-- where sanitizedBio = DOMPurify.sanitize(userBio) -->


<!-- Handlebars -->
<!-- ❌ INSECURE — triple braces render raw HTML -->
<div>{{{userComment}}}</div>

<!-- ✅ SECURE — double braces auto-escape -->
<div>{{userComment}}</div>


<!-- Pug -->
//- ❌ INSECURE — != renders raw HTML
div!= userInput

//- ✅ SECURE — = auto-escapes
div= userInput
```

---

## 13. Mass Assignment via `req.body`

**Vulnerability:** Passing `req.body` directly to ORM `create()` or `update()` methods allows attackers to set fields they should not control — such as `isAdmin: true`, `role: 'admin'`, `credits: 9999`, or `verified: true`. This is Express's most common privilege escalation vulnerability.

**References:** CWE-915, OWASP A03:2025

### Mandatory Rules

- **Never pass `req.body` directly to ORM model creation or update methods** — always explicitly pick allowed fields.
- **Define an input DTO or allowlist** for each endpoint — extract only the fields the caller is permitted to set.
- **Validate the extracted fields with a schema validator** (Zod, Joi, Yup, express-validator) before using them.
- **Derive privileged fields from the authenticated session**, not from the request body (e.g., `userId` comes from `req.user.id`, never from `req.body.userId`).

```javascript
// ❌ INSECURE — mass assignment: body { "role": "admin", "credits": 9999 }
app.post('/api/users', async (req, res) => {
  const user = await User.create(req.body); // sets any field ❌
  res.json(user);
});

// ❌ INSECURE — update: body { "isAdmin": true }
app.put('/api/users/:id', authenticate, async (req, res) => {
  await User.update(req.body, { where: { id: req.params.id } }); // ❌
});

// ✅ SECURE — explicit field extraction with Zod validation
const { z } = require('zod');

const CreateUserSchema = z.object({
  email: z.string().email().max(255),
  username: z.string().min(3).max(50),
  password: z.string().min(12).max(128),
  // role, isAdmin, credits NOT included — server sets defaults
});

app.post('/api/users', async (req, res, next) => {
  try {
    const input = CreateUserSchema.parse(req.body);
    const hashedPassword = await bcrypt.hash(input.password, 12);
    const user = await User.create({
      email: input.email,
      username: input.username,
      passwordHash: hashedPassword,
      role: 'user',        // hardcoded server-side
      isAdmin: false,      // hardcoded server-side
    });
    res.status(201).json({ id: user.id, email: user.email, username: user.username });
  } catch (err) {
    if (err instanceof z.ZodError) return res.status(400).json({ errors: err.issues });
    next(err);
  }
});
```

---

## 14. File Upload Security — Multer

**Vulnerability:** `multer` without configuration allows uploading files of any type, any size, and with any filename — enabling remote code execution (uploading a `.php` file to a web-served directory), DoS via large files, and stored XSS via SVG uploads.

**References:** CWE-434, CWE-400, OWASP A04:2025

### Mandatory Rules

- **Set explicit `limits` in multer** — `fileSize` (e.g., 10MB), `files` (e.g., 5), and `fields` counts.
- **Validate file types by magic bytes**, not by `mimetype` or `originalname` — the client controls both. Use `file-type` to detect the actual file type from the buffer.
- **Never preserve the original filename** — generate a UUID with the allowed extension for stored files.
- **Store uploads outside the web root** (not in `public/`) and serve them through a controlled handler with `Content-Disposition: attachment`.
- **Scan uploads for malware** using ClamAV or a cloud API in high-security contexts.

```javascript
// ❌ INSECURE — no file type check, no size limit, original filename preserved
const multer = require('multer');
const upload = multer({ dest: 'public/uploads/' }); // public = serve directly ❌
app.post('/upload', upload.single('file'), (req, res) => {
  res.json({ path: req.file.path }); // original name exposed ❌
});

// ✅ SECURE — hardened multer with type validation
const multer = require('multer');
const { fileTypeFromBuffer } = require('file-type');
const { randomUUID } = require('crypto');
const path = require('path');
const fs = require('fs/promises');

const UPLOADS_DIR = path.resolve(__dirname, '../private-uploads');
const ALLOWED_MIME_TYPES = new Set(['image/jpeg', 'image/png', 'image/webp', 'application/pdf']);
const ALLOWED_EXTENSIONS = { 'image/jpeg': '.jpg', 'image/png': '.png', 'image/webp': '.webp', 'application/pdf': '.pdf' };

const upload = multer({
  storage: multer.memoryStorage(), // buffer — inspect before writing
  limits: {
    fileSize: 10 * 1024 * 1024,   // 10 MB max per file
    files: 5,                      // max 5 files
  },
});

app.post('/upload', authenticate, upload.single('file'), async (req, res, next) => {
  try {
    if (!req.file) return res.status(400).json({ error: 'No file uploaded' });

    // Validate magic bytes (not mimetype claim)
    const detected = await fileTypeFromBuffer(req.file.buffer);
    if (!detected || !ALLOWED_MIME_TYPES.has(detected.mime)) {
      return res.status(400).json({ error: 'Invalid file type' });
    }

    // Write with UUID filename outside web root
    const filename = `${randomUUID()}${ALLOWED_EXTENSIONS[detected.mime]}`;
    const destPath = path.join(UPLOADS_DIR, filename);
    await fs.writeFile(destPath, req.file.buffer);

    res.json({ fileId: filename });
  } catch (err) {
    next(err);
  }
});

// Serve files with Content-Disposition: attachment
app.get('/files/:fileId', authenticate, async (req, res, next) => {
  const fileId = req.params.fileId;
  if (!/^[\w-]+\.(jpg|png|webp|pdf)$/.test(fileId)) {
    return res.status(400).json({ error: 'Invalid file ID' });
  }
  const fullPath = path.resolve(UPLOADS_DIR, fileId);
  if (!fullPath.startsWith(UPLOADS_DIR + path.sep)) {
    return res.status(403).json({ error: 'Access denied' });
  }
  res.setHeader('Content-Disposition', `attachment; filename="${fileId}"`);
  res.sendFile(fullPath);
});
```

---

## 15. Error Handling — Information Exposure

**Vulnerability:** Express's default error handler sends stack traces, internal file paths, and error messages to clients in development mode. In production, these leaks reveal application architecture, dependency versions, and vulnerability hints to attackers. Even in custom error handlers, accidentally serializing `Error` objects exposes stack traces.

**References:** CWE-209, CWE-497, OWASP A05:2025

### Mandatory Rules

- **Never send `err.stack`, `err.message`, or raw `Error` objects to clients in production** — log the full error server-side, return a generic message.
- **Implement a centralized Express error handler** (`app.use((err, req, res, next) => {...})`) as the last middleware — all thrown errors and `next(err)` calls flow here.
- **Distinguish operational errors from programmer errors** — return 4xx for validation/auth errors, 5xx for unexpected errors.
- **Remove `X-Powered-By: Express`** — Helmet does this, but also `app.disable('x-powered-by')`.
- **Use structured logging** (Winston, Pino) and ship logs to a centralized store — never rely on `console.log` in production.

```javascript
// ❌ INSECURE — stack trace in response body
app.use((err, req, res, next) => {
  res.status(err.status || 500).json({
    error: err.message,  // exposes internal details ❌
    stack: err.stack,    // reveals file paths and line numbers ❌
  });
});

// ❌ INSECURE — serializing Error object directly
res.status(500).json(err); // Error.toJSON is undefined, but some serializers expose stack

// ✅ SECURE — centralized error handler with logging
const pino = require('pino');
const logger = pino({ level: process.env.LOG_LEVEL || 'info' });

app.use((err, req, res, next) => {
  // Log full error details server-side
  logger.error({
    err,
    req: { method: req.method, url: req.url, ip: req.ip },
  }, 'Unhandled error');

  // Operational errors (4xx): safe to expose message
  if (err.isOperational) {
    return res.status(err.statusCode || 400).json({ error: err.message });
  }

  // Programmer/unexpected errors (5xx): generic message only
  res.status(500).json({ error: 'An unexpected error occurred. Please try again later.' });
});

// Helper: operational error class
class AppError extends Error {
  constructor(message, statusCode) {
    super(message);
    this.statusCode = statusCode;
    this.isOperational = true;
    Error.captureStackTrace(this, this.constructor);
  }
}
```

---

## 16. Supply Chain — Dependencies and Known CVEs

**Vulnerability:** Express applications depend on hundreds of npm packages. Key CVEs affect common Express middleware: `qs` prototype pollution (used by `body-parser`), `ip` package SSRF bypass (used by `express-rate-limit`), and various JSON deserialization vulnerabilities.

**References:** CWE-1395, OWASP A06:2025

### Mandatory Rules

- **Run `npm audit --audit-level=high` in CI** — fail the pipeline on high/critical vulnerabilities.
- **Pin exact versions** or use conservative ranges (`~`) in `package.json` and commit `package-lock.json`.
- **Keep key dependencies at minimum versions** — `qs >= 6.7.3` (CVE-2022-24999 prototype pollution), `express-rate-limit >= 7.5.0` (CVE-2024-29415 IP bypass), `jsonwebtoken >= 9.0.0` (CVE-2022-23529 arbitrary file read).
- **Use `express-validator` or `zod` for all input validation** — never trust `req.body`, `req.params`, or `req.query` without schema validation.
- **Limit `express.json()` body size** — default is 100kb; set `{ limit: '10kb' }` for most APIs to prevent JSON DoS.

```javascript
// ✅ SECURE — hardened body parsing with size limits
app.use(express.json({ limit: '10kb', strict: true }));
app.use(express.urlencoded({ extended: false, limit: '10kb' }));

// ✅ SECURE — input validation with express-validator
const { body, param, validationResult } = require('express-validator');

const createUserValidation = [
  body('email').isEmail().normalizeEmail().isLength({ max: 255 }),
  body('username').isAlphanumeric().isLength({ min: 3, max: 50 }).trim().escape(),
  body('password').isLength({ min: 12, max: 128 }),
];

app.post('/api/users', createUserValidation, (req, res, next) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({ errors: errors.array() });
  }
  next();
}, createUserHandler);
```

```bash
# CI pipeline
npm audit --audit-level=high
npx better-npm-audit audit --level high

# Check specific dependency versions
npm list qs express-rate-limit jsonwebtoken multer
```

---

## CVE Reference Table

| CVE | Severity | Component | Description | Fixed In |
|-----|----------|-----------|-------------|----------|
| CVE-2024-29415 | High (9.1) | ip < 1.1.9 / ip 2.x < 2.0.1 (via express-rate-limit) | `::ffff:127.0.0.1` misclassified as non-loopback, bypassing IP-based rate limiting | ip 1.1.9 / express-rate-limit 7.5.0 |
| CVE-2022-24999 | High (7.5) | qs < 6.7.3 (via body-parser) | Prototype pollution via crafted query string object (`__proto__[x]=y`) | qs 6.7.3 |
| CVE-2022-23529 | High (7.6) | jsonwebtoken < 9.0.0 | Arbitrary file read via crafted `secretOrPublicKey` object in `jwt.verify()` | jsonwebtoken 9.0.0 |
| CVE-2022-25912 | High (7.5) | serve-static < 1.15.0 | Path traversal via URL-encoded paths allows reading files outside the static root | serve-static 1.15.0 |
| CVE-2023-26159 | Medium (6.1) | follow-redirects < 1.15.4 | Open redirect via `url.hostname` vs `url.host` comparison bypass | follow-redirects 1.15.4 |
| CVE-2022-21803 | High (7.4) | nconf < 0.12.1 | Prototype pollution in `nconf.set()` and `nconf.merge()` | nconf 0.12.1 |
| CVE-2021-23337 | High (7.2) | lodash < 4.17.21 | Command injection in `_.template()` and prototype pollution in `_.merge()` | lodash 4.17.21 |
| CVE-2021-3918 | Critical (9.8) | json-schema < 0.4.0 | Prototype pollution via `json-schema` validation (transitive dep of many packages) | json-schema 0.4.0 |
| CVE-2017-16138 | High (7.5) | mime < 1.4.1 / mime 2.x < 2.0.3 | ReDoS via crafted MIME type string | mime 1.4.1, 2.0.3 |
| CVE-2015-9235 | Critical (9.8) | jsonwebtoken < 4.2.2 | `alg: 'none'` accepted without verification, bypassing JWT signature | jsonwebtoken 4.2.2 |

---

## Security Checklist

### Middleware and Architecture
- [ ] Authentication middleware registered BEFORE protected route handlers
- [ ] `helmet()` installed as the first middleware
- [ ] `app.disable('x-powered-by')` called
- [ ] Global and per-endpoint rate limiting configured
- [ ] Body size limits set (`express.json({ limit: '10kb' })`)
- [ ] `app.use('*', notFoundHandler)` registered last

### Injection Prevention
- [ ] All SQL queries use parameterized queries (`$1`, `?`, or named bindings)
- [ ] No string interpolation into SQL, MongoDB queries, or shell commands
- [ ] `express-mongo-sanitize` applied for MongoDB applications
- [ ] No `child_process.exec()` / `execSync()` with user input
- [ ] `spawn()` called with `shell: false` and argument array
- [ ] Path operations canonicalized and prefix-checked against base directory
- [ ] `express.static()` configured with `dotfiles: 'deny'` and `index: false`

### Authentication and Sessions
- [ ] Session secret stored in environment variable (min 32 random bytes)
- [ ] Session cookie: `httpOnly`, `secure`, `sameSite` flags set
- [ ] Persistent session store (Redis, PostgreSQL) used — no in-memory store
- [ ] Session regenerated on login (prevent session fixation)
- [ ] Session destroyed on logout
- [ ] JWT `algorithms` explicitly specified — `none` not accepted
- [ ] JWT `exp`, `iss`, `aud` claims validated
- [ ] JWTs stored in `HttpOnly` cookies, not `localStorage`

### Input and Authorization
- [ ] `req.body` never passed directly to ORM `create()`/`update()` (no mass assignment)
- [ ] Input validated with Zod, Joi, or `express-validator` on every endpoint
- [ ] CSRF protection implemented for session-authenticated state-changing routes
- [ ] CORS `origin` is an explicit allowlist, not wildcard or reflected
- [ ] Template engines use escaped output (`<%= %>`, `{{ }}`, `= `) not raw variants

### File Uploads
- [ ] Multer `fileSize` and `files` limits configured
- [ ] File type validated by magic bytes (`file-type` library)
- [ ] Original filename discarded — UUID used for stored files
- [ ] Uploads stored outside web root (not in `public/`)
- [ ] Files served with `Content-Disposition: attachment`

### Error Handling and Logging
- [ ] Centralized error handler as last middleware
- [ ] No `err.stack` or `err.message` in production responses
- [ ] Structured logging with Pino or Winston
- [ ] Sensitive data (passwords, tokens) never logged

### Supply Chain
- [ ] `npm audit --audit-level=high` passes in CI
- [ ] `qs >= 6.7.3` (CVE-2022-24999)
- [ ] `jsonwebtoken >= 9.0.0` (CVE-2022-23529)
- [ ] `express-rate-limit >= 7.5.0` (CVE-2024-29415)
- [ ] `package-lock.json` committed and integrity verified

---

## Tooling

| Tool | Purpose | Command |
|------|---------|---------|
| [npm audit](https://docs.npmjs.com/cli/audit) | Dependency vulnerability scanning | `npm audit --audit-level=high` |
| [Snyk](https://snyk.io) | Continuous dependency and code scanning | `npx snyk test` |
| [helmet](https://helmetjs.github.io) | Security HTTP headers | `npm install helmet` |
| [express-rate-limit](https://github.com/express-rate-limit/express-rate-limit) | Rate limiting middleware | `npm install express-rate-limit` |
| [express-mongo-sanitize](https://github.com/fiznool/express-mongo-sanitize) | NoSQL injection prevention | `npm install express-mongo-sanitize` |
| [csrf-csrf](https://github.com/Psifi-Solutions/csrf-csrf) | CSRF protection (csurf successor) | `npm install csrf-csrf` |
| [zod](https://zod.dev) | Schema validation | `npm install zod` |
| [express-validator](https://express-validator.github.io) | Request validation middleware | `npm install express-validator` |
| [file-type](https://github.com/sindresorhus/file-type) | Magic byte file type detection | `npm install file-type` |
| [Semgrep](https://semgrep.dev) | Static analysis for Node.js/Express | `semgrep --config p/nodejs` |
| [njsscan](https://github.com/ajinabraham/njsscan) | Node.js security SAST scanner | `npx njsscan .` |
| [ESLint + security plugin](https://github.com/eslint-community/eslint-plugin-security) | Security-focused lint rules | `npm install -D eslint-plugin-security` |
