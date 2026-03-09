# 🐈 NestJS Security Rules

> **Standard:** Secure coding rules for NestJS applications (v9/v10/v11), covering Guards, Pipes, Interceptors, authentication, authorization, database access, microservices, WebSockets, and GraphQL.
> **Sources:** OWASP API Top 10:2023, NestJS official security docs, class-transformer/class-validator advisories, CVE database, Snyk advisories, PortSwigger research
> **Version:** 1.0.0
> **Last updated:** March 2026
> **Scope:** NestJS framework patterns — Guards, Pipes, Interceptors, Modules, Providers, HTTP Module, WebSockets, Microservices, and GraphQL. Underlying Express/Fastify rules apply alongside these.

---

## General Instructions

Apply these rules to all NestJS code generation, review, and refactoring tasks. NestJS's dependency injection and decorator-based architecture introduce unique security patterns: Guards control access but only run when properly bound, Pipes validate input but must be configured strictly, and Interceptors transform responses but can accidentally expose sensitive fields. Always verify the complete request lifecycle — Guard → Interceptor → Pipe → Handler — when reviewing authorization and validation flows.

---

## 1. Guard Execution Order & Bypass

**Vulnerability:** NestJS Guards only run when explicitly bound to a controller, route, or globally. Forgetting to attach a Guard, binding it at the wrong scope, or placing route decorators before Guards allows unauthenticated/unauthorized access. Local Guards override global Guards by default.

**References:** CWE-284, CWE-862, OWASP API2:2023

### Mandatory Rules

- **Register authentication Guards globally** via `APP_GUARD` provider so they apply to every route unless explicitly opted out — never rely on per-controller binding for auth.
- **Use `@Public()` decorator pattern** to explicitly mark public routes — deny by default, allow by exception.
- **Never place `@UseGuards()` after route decorators** — execution order follows decorator application order in TypeScript (bottom-up, so Guards must be closest to the class/method).
- **Never use `canActivate(): boolean` returning `true`** as a placeholder — remove stub Guards before shipping.

```typescript
// ❌ INSECURE — Guard forgotten on controller; all routes are public
@Controller('admin')
export class AdminController {
  @Get('users')
  getUsers() { ... }
}

// ❌ INSECURE — Local guard without global default; other controllers unprotected
@Controller('admin')
@UseGuards(JwtAuthGuard)
export class AdminController { ... }

// ✅ SECURE — Global guard via APP_GUARD; explicit @Public() for opt-out
// app.module.ts
providers: [
  { provide: APP_GUARD, useClass: JwtAuthGuard },
  { provide: APP_GUARD, useClass: RolesGuard },
]

// jwt-auth.guard.ts
@Injectable()
export class JwtAuthGuard extends AuthGuard('jwt') {
  canActivate(context: ExecutionContext) {
    const isPublic = this.reflector.getAllAndOverride<boolean>(IS_PUBLIC_KEY, [
      context.getHandler(),
      context.getClass(),
    ]);
    if (isPublic) return true;
    return super.canActivate(context);
  }
}

// public.decorator.ts
export const IS_PUBLIC_KEY = 'isPublic';
export const Public = () => SetMetadata(IS_PUBLIC_KEY, true);

// public route usage
@Public()
@Get('health')
healthCheck() { return 'ok'; }
```

---

## 2. Validation Pipe & Mass Assignment

**Vulnerability:** Without `ValidationPipe` set to `whitelist: true`, any property in the request body is passed to DTOs and potentially persisted. An attacker can inject fields like `isAdmin`, `role`, or `id` that bypass application-level access controls.

**References:** CWE-915, OWASP API6:2023

### Mandatory Rules

- **Enable `ValidationPipe` globally** with `whitelist: true` and `forbidNonWhitelisted: true` — strip and reject any properties not declared in the DTO.
- **Never pass `req.body` or raw plain objects directly** to repository methods — always use typed DTOs validated by the Pipe.
- **Set `transform: true`** to automatically coerce types, preventing type confusion attacks.
- **Use `plainToInstance` with `excludeExtraneousValues: true`** when manually mapping plain objects to class instances.
- **Never use `skipMissingProperties: true` on security-critical DTOs** — missing required fields should fail validation, not silently pass.

```typescript
// ❌ INSECURE — No validation; attacker sends { username: "x", isAdmin: true }
@Post('register')
register(@Body() body: any) {
  return this.usersService.create(body); // isAdmin poisoned
}

// ❌ INSECURE — ValidationPipe without whitelist; extra fields pass through
app.useGlobalPipes(new ValidationPipe());

// ✅ SECURE — Global strict ValidationPipe
// main.ts
app.useGlobalPipes(
  new ValidationPipe({
    whitelist: true,           // strip properties not in DTO
    forbidNonWhitelisted: true, // reject requests with extra properties
    transform: true,           // coerce types to DTO class instances
    transformOptions: { enableImplicitConversion: true },
  }),
);

// create-user.dto.ts
export class CreateUserDto {
  @IsEmail()
  email: string;

  @IsString()
  @MinLength(12)
  password: string;
  // isAdmin is NOT in DTO — will be stripped automatically
}

// users.service.ts
async create(dto: CreateUserDto) {
  const hash = await bcrypt.hash(dto.password, 12);
  return this.usersRepository.save({ email: dto.email, passwordHash: hash });
  // never: this.usersRepository.save(dto) — DTO may contain fields after mapping
}
```

---

## 3. class-transformer Prototype Pollution & ReDoS

**Vulnerability:** `class-transformer` versions before 0.5.1 are vulnerable to prototype pollution (CVE-2022-21190). Using `plainToClass`/`plainToInstance` with untrusted input and permissive exclusion strategies can pollute `Object.prototype`. Additionally, `class-validator` regex validators on user input can trigger ReDoS (CVE-2023-26108, CVE-2023-26115).

**References:** CVE-2022-21190, CVE-2023-26108, CVE-2023-26115, CWE-1321, CWE-400

### Mandatory Rules

- **Pin `class-transformer` to `>=0.5.1`** and `class-validator` to `>=0.14.0` — earlier versions have prototype pollution and ReDoS vulnerabilities.
- **Use `excludeExtraneousValues: true`** with `@Expose()` allowlist strategy rather than `excludePrefix` strategies.
- **Never call `plainToInstance` on deeply nested user-controlled objects** without input length limits.
- **Audit custom `@Matches()` regex patterns** for ReDoS — use bounded quantifiers and avoid catastrophic backtracking.
- **Use `@MaxLength()` before `@Matches()`** so ReDoS-prone patterns only run on bounded strings.

```typescript
// ❌ INSECURE — class-transformer < 0.5.1 prototype pollution via __proto__
// Input: { "__proto__": { "isAdmin": true } }
const obj = plainToClass(UserDto, req.body);

// ❌ INSECURE — ReDoS via unbounded regex on user input
@IsString()
@Matches(/^([a-zA-Z0-9]+\s?)*$/) // catastrophic backtracking
username: string;

// ✅ SECURE — Use allowlist strategy + bounded string + safe regex
export class UserSearchDto {
  @IsString()
  @MaxLength(50)               // bound before regex
  @Matches(/^[a-zA-Z0-9_-]+$/) // no backtracking — simple character class
  username: string;
}

// ✅ SECURE — plainToInstance with excludeExtraneousValues
@Exclude()
export class UserResponseDto {
  @Expose() id: number;
  @Expose() email: string;
  // passwordHash not exposed — Exclude() decorator on class
}

const safe = plainToInstance(UserResponseDto, user, {
  excludeExtraneousValues: true,
  strategy: 'excludeAll',
});
```

---

## 4. Passport Authentication & JWT Strategy

**Vulnerability:** `@nestjs/passport` JwtStrategy misconfiguration — using `algorithms: ['none']`, trusting the token's own `alg` header, skipping `issuer`/`audience` validation, or using weak secrets — allows attackers to forge authentication tokens.

**References:** CVE-2022-23529, CWE-347, CWE-798

### Mandatory Rules

- **Always specify `algorithms` explicitly** in `JwtStrategy` — never allow the algorithm to be determined by the token header.
- **Never use `ignoreExpiration: true`** in production `JwtModule` configuration.
- **Validate `issuer` and `audience`** claims to prevent token reuse across services.
- **Source JWT secret from `ConfigService`** — never hardcode in `JwtModule.register()`.
- **Use `passReqToCallback: true` only** when you need the raw request — otherwise keep strategy stateless.
- **Store JWTs in `HttpOnly` cookies**, not `localStorage` — set `sameSite: 'strict'` and `secure: true`.

```typescript
// ❌ INSECURE — hardcoded secret, no algorithm constraint, no expiry validation
JwtModule.register({
  secret: 'mysecret',
  signOptions: { expiresIn: '7d' },
})

@Injectable()
export class JwtStrategy extends PassportStrategy(Strategy) {
  constructor() {
    super({ jwtFromRequest: ExtractJwt.fromAuthHeaderAsBearerToken() });
    // missing: secretOrKey, algorithms, issuer, audience
  }
}

// ✅ SECURE — Strict JWT strategy
@Injectable()
export class JwtStrategy extends PassportStrategy(Strategy) {
  constructor(private config: ConfigService) {
    super({
      jwtFromRequest: ExtractJwt.fromExtractors([
        (req) => req?.cookies?.access_token, // HttpOnly cookie
      ]),
      secretOrKey: config.getOrThrow<string>('JWT_SECRET'),
      algorithms: ['HS256'],   // explicit — rejects alg:none and RS256 confusion
      issuer: config.getOrThrow<string>('JWT_ISSUER'),
      audience: config.getOrThrow<string>('JWT_AUDIENCE'),
      ignoreExpiration: false, // always validate exp
    });
  }

  async validate(payload: JwtPayload) {
    const user = await this.usersService.findById(payload.sub);
    if (!user || !user.isActive) throw new UnauthorizedException();
    return user; // attached to req.user
  }
}

// ✅ SECURE — Issue tokens with full claims
this.jwtService.sign(
  { sub: user.id, email: user.email, roles: user.roles },
  {
    expiresIn: '15m',
    issuer: this.config.getOrThrow('JWT_ISSUER'),
    audience: this.config.getOrThrow('JWT_AUDIENCE'),
  },
)
```

---

## 5. Role-Based Authorization & RBAC

**Vulnerability:** Client-side or DTO-level role checks that are not enforced by server-side Guards allow privilege escalation. Using `req.user.roles` from a JWT payload without server-side verification of the role's current validity (e.g., revoked admin) is also dangerous.

**References:** CWE-285, CWE-269, OWASP API5:2023

### Mandatory Rules

- **Implement RBAC via Guards registered as `APP_GUARD`** — never perform authorization in service or repository layers as the sole control.
- **Re-verify sensitive roles against the database** for high-privilege operations — JWT payload roles may be stale.
- **Use custom `@Roles()` decorator + `RolesGuard`** pattern — never inline role checks with `if (req.user.role === 'admin')` scattered across controllers.
- **Use resource-level authorization (ABAC)** for operations on user-owned data — verify `resource.ownerId === req.user.id`.

```typescript
// ❌ INSECURE — Role check in service layer; Guard could be skipped
async deleteUser(requesterId: number, targetId: number) {
  const requester = await this.find(requesterId);
  if (requester.role !== 'admin') throw new ForbiddenException();
  // if Guard is misconfigured above, this is the only check
}

// ✅ SECURE — Roles Guard as APP_GUARD
// roles.decorator.ts
export const Roles = (...roles: Role[]) => SetMetadata(ROLES_KEY, roles);

// roles.guard.ts
@Injectable()
export class RolesGuard implements CanActivate {
  constructor(private reflector: Reflector) {}

  canActivate(context: ExecutionContext): boolean {
    const required = this.reflector.getAllAndOverride<Role[]>(ROLES_KEY, [
      context.getHandler(),
      context.getClass(),
    ]);
    if (!required?.length) return true;
    const { user } = context.switchToHttp().getRequest();
    return required.some((role) => user?.roles?.includes(role));
  }
}

// admin.controller.ts
@Roles(Role.ADMIN)
@Delete('users/:id')
deleteUser(@Param('id', ParseIntPipe) id: number) { ... }

// ✅ SECURE — Resource ownership check (ABAC)
@Patch('posts/:id')
async updatePost(
  @Param('id', ParseIntPipe) id: number,
  @CurrentUser() user: User,
  @Body() dto: UpdatePostDto,
) {
  const post = await this.postsService.findOne(id);
  if (post.authorId !== user.id && !user.roles.includes(Role.ADMIN)) {
    throw new ForbiddenException();
  }
  return this.postsService.update(id, dto);
}
```

---

## 6. Database Security (TypeORM & Prisma Raw Queries)

**Vulnerability:** TypeORM's `query()` and `createQueryBuilder()` with string interpolation, and Prisma's `$queryRaw` with template literals using `${}` instead of `Prisma.sql` tagged templates, produce SQL injection vulnerabilities.

**References:** CWE-89, OWASP API8:2023

### Mandatory Rules

- **Never use TypeORM `.query()`** with string concatenation or template literal interpolation of user input.
- **Use TypeORM repository methods** (`find()`, `findOne()`, `save()`) or parameterized `createQueryBuilder()` with `.setParameter()`.
- **For Prisma raw queries, always use `Prisma.sql` tagged template** — never interpolate user values into `$queryRaw` with `${}`.
- **Use `FindOptionsWhere` typed objects** instead of raw where strings in TypeORM.
- **Avoid `TypeOrmModule.forRoot({ logging: true })`** in production — it logs all queries including parameter values.

```typescript
// ❌ INSECURE — TypeORM raw query with string interpolation
async findByEmail(email: string) {
  return this.dataSource.query(`SELECT * FROM users WHERE email = '${email}'`);
}

// ❌ INSECURE — Prisma $queryRaw with ${} interpolation
async searchUsers(name: string) {
  return this.prisma.$queryRaw`SELECT * FROM users WHERE name = ${name}`;
  // Wait — this IS safe with Prisma.sql! The issue is ${} in a regular string:
}
async searchUsersBad(name: string) {
  return this.prisma.$queryRaw(
    Prisma.raw(`SELECT * FROM users WHERE name = '${name}'`) // ❌ INSECURE
  );
}

// ✅ SECURE — TypeORM parameterized query
async findByEmail(email: string) {
  return this.dataSource.query('SELECT * FROM users WHERE email = $1', [email]);
}

// ✅ SECURE — TypeORM repository (safe by default)
async findByEmail(email: string) {
  return this.usersRepository.findOne({ where: { email } });
}

// ✅ SECURE — TypeORM QueryBuilder with named parameters
async searchByName(name: string) {
  return this.usersRepository
    .createQueryBuilder('user')
    .where('user.name ILIKE :name', { name: `%${name}%` })
    .getMany();
}

// ✅ SECURE — Prisma raw query with tagged template (auto-parameterized)
async searchUsers(name: string) {
  return this.prisma.$queryRaw`SELECT * FROM users WHERE name ILIKE ${`%${name}%`}`;
  // Prisma tagged templates auto-parameterize interpolated values
}
```

---

## 7. ConfigModule & Secret Management

**Vulnerability:** Exposing environment variables via `ConfigModule` with `isGlobal: true` and no schema validation leads to missing secrets silently defaulting to `undefined`. Logging config at startup, returning config in API responses, or using `process.env` directly in providers bypasses schema validation.

**References:** CWE-312, CWE-798, CWE-209

### Mandatory Rules

- **Use `ConfigService.getOrThrow()`** instead of `get()` for all required secrets — fail fast on missing config at startup.
- **Validate config schema with Joi or Zod** in `ConfigModule.forRoot({ validationSchema })` — reject startup if required env vars are absent.
- **Never return configuration objects in API responses** — they may contain secrets.
- **Never log config values** — mask secrets in structured logging.
- **Use `@nestjs/config` `ConfigModule`** rather than accessing `process.env` directly in providers to ensure validation runs.

```typescript
// ❌ INSECURE — No validation; undefined JWT_SECRET causes silent failures
ConfigModule.forRoot({ isGlobal: true })
const secret = this.config.get('JWT_SECRET'); // undefined if missing

// ❌ INSECURE — Exposing config endpoint
@Get('debug/config')
getConfig() {
  return process.env; // exposes all secrets
}

// ✅ SECURE — Joi validation schema at startup
import * as Joi from 'joi';
ConfigModule.forRoot({
  isGlobal: true,
  validationSchema: Joi.object({
    NODE_ENV:       Joi.string().valid('development','production','test').required(),
    DATABASE_URL:   Joi.string().uri().required(),
    JWT_SECRET:     Joi.string().min(32).required(),
    JWT_ISSUER:     Joi.string().uri().required(),
    JWT_AUDIENCE:   Joi.string().required(),
    REDIS_URL:      Joi.string().uri().required(),
  }),
  validationOptions: { abortEarly: true },
})

// ✅ SECURE — Fail-fast secret access
@Injectable()
export class AuthService {
  constructor(private config: ConfigService) {
    // Validates secret is present at service instantiation
    this.jwtSecret = config.getOrThrow<string>('JWT_SECRET');
  }
}
```

---

## 8. CORS Misconfiguration

**Vulnerability:** Setting `origin: true` (reflect all origins), `origin: '*'` with credentials, or deriving allowed origins from request headers at runtime enables cross-origin attacks. NestJS's `enableCors()` accepts these unsafe shortcuts.

**References:** CWE-346, OWASP API7:2023

### Mandatory Rules

- **Never use `origin: true` or `origin: '*'` with `credentials: true`** — browsers block this, but attackers can bypass with non-browser clients.
- **Use an explicit allowlist** of known origins — validate against a `Set<string>`.
- **Set `credentials: true` only for first-party frontends** — never for public APIs.
- **Apply CORS at the NestJS level** (not only at a reverse proxy) so server-to-server calls are also restricted.

```typescript
// ❌ INSECURE — Reflect all origins (mirrors request Origin header)
app.enableCors({ origin: true, credentials: true });

// ❌ INSECURE — Wildcard with credentials (browsers block, but still bad policy)
app.enableCors({ origin: '*', credentials: true });

// ✅ SECURE — Explicit origin allowlist
const ALLOWED_ORIGINS = new Set(
  (process.env.CORS_ORIGINS ?? '').split(',').filter(Boolean),
);

app.enableCors({
  origin: (origin, callback) => {
    if (!origin || ALLOWED_ORIGINS.has(origin)) {
      callback(null, true);
    } else {
      callback(new Error(`CORS policy violation: ${origin}`));
    }
  },
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'PATCH', 'DELETE'],
  allowedHeaders: ['Content-Type', 'Authorization'],
  maxAge: 600,
});
```

---

## 9. Helmet & Security Headers

**Vulnerability:** NestJS does not set security headers by default. Without Helmet, responses lack `Content-Security-Policy`, `X-Frame-Options`, `X-Content-Type-Options`, and other headers that prevent clickjacking, MIME sniffing, and XSS.

**References:** OWASP A05:2021, CWE-693

### Mandatory Rules

- **Apply `helmet()` as the first middleware** in `main.ts` before all other middleware and application setup.
- **Configure a strict Content Security Policy** — do not use `helmet()` defaults for production without review.
- **Disable `X-Powered-By`** — NestJS sets it to `Express`; Helmet removes it, but verify.
- **Use `compression()` only after verifying** the API is not vulnerable to BREACH attack on compressed responses containing secrets.

```typescript
// ❌ INSECURE — No security headers
async function bootstrap() {
  const app = await NestFactory.create(AppModule);
  await app.listen(3000);
}

// ✅ SECURE — Helmet with custom CSP
import helmet from 'helmet';

async function bootstrap() {
  const app = await NestFactory.create(AppModule);

  app.use(helmet({
    contentSecurityPolicy: {
      directives: {
        defaultSrc: ["'self'"],
        scriptSrc:  ["'self'"],
        styleSrc:   ["'self'", "'unsafe-inline'"], // tighten if possible
        imgSrc:     ["'self'", 'data:', 'https:'],
        connectSrc: ["'self'"],
        fontSrc:    ["'self'"],
        objectSrc:  ["'none'"],
        frameSrc:   ["'none'"],
        upgradeInsecureRequests: [],
      },
    },
    hsts: { maxAge: 31536000, includeSubDomains: true, preload: true },
    referrerPolicy: { policy: 'strict-origin-when-cross-origin' },
  }));

  app.enableCors({ ... });
  await app.listen(3000);
}
```

---

## 10. Rate Limiting with @nestjs/throttler

**Vulnerability:** Without rate limiting, NestJS API endpoints are vulnerable to brute-force attacks on authentication, credential stuffing, and resource exhaustion. The default `ThrottlerGuard` uses in-memory storage unsuitable for multi-instance deployments.

**References:** CWE-307, CWE-400, OWASP API4:2023

### Mandatory Rules

- **Register `ThrottlerGuard` as a global `APP_GUARD`** so all routes are rate-limited by default.
- **Use Redis-backed `ThrottlerStorageRedisService`** in production — in-memory throttling is per-instance and bypassable with multiple servers.
- **Apply stricter throttle limits** to authentication routes (`/auth/login`, `/auth/register`, `/auth/reset-password`) with `@Throttle({ default: { limit: 5, ttl: 60000 } })`.
- **Throttle by user ID** (after auth) for authenticated routes — IP-based throttling is bypassed by botnets.
- **Include `throttler-behind-proxy: true`** (or configure `getTracker`) when behind a load balancer to read real client IPs.

```typescript
// ❌ INSECURE — No rate limiting; brute-force possible
@Post('auth/login')
login(@Body() dto: LoginDto) { ... }

// ❌ INSECURE — In-memory throttler (per-instance, not production-safe)
ThrottlerModule.forRoot([{ ttl: 60000, limit: 100 }])

// ✅ SECURE — Redis-backed throttler with global guard
// app.module.ts
ThrottlerModule.forRootAsync({
  imports: [ConfigModule],
  inject: [ConfigService],
  useFactory: (config: ConfigService) => ({
    throttlers: [{ ttl: 60_000, limit: 100 }],
    storage: new ThrottlerStorageRedisService(
      new Redis(config.getOrThrow('REDIS_URL'))
    ),
    getTracker: (req) => req.ips.length ? req.ips[0] : req.ip, // behind proxy
  }),
})
providers: [{ provide: APP_GUARD, useClass: ThrottlerGuard }]

// auth.controller.ts — stricter limits on login endpoint
@Throttle({ default: { limit: 5, ttl: 60_000 } }) // 5 attempts per minute
@SkipThrottle({ default: false })
@Post('login')
login(@Body() dto: LoginDto) { ... }
```

---

## 11. File Upload Security

**Vulnerability:** `@UploadedFile()` with default multer configuration stores files on disk with original filenames, lacks file type validation, allows arbitrary upload sizes, and stores files in the web root — enabling remote code execution via uploaded scripts and path traversal.

**References:** CWE-434, CWE-22, OWASP A04:2021

### Mandatory Rules

- **Use `memoryStorage()`** and validate magic bytes with the `file-type` package — never rely on `mimetype` from the multipart header (attacker-controlled).
- **Reject files exceeding size limits** via `limits: { fileSize: MAX_BYTES }` in `multerOptions`.
- **Save files with UUID filenames** — never preserve `originalname` on disk.
- **Store uploads outside the web root** — serve through a dedicated download endpoint with `Content-Disposition: attachment`.
- **Validate file extension using an allowlist** in addition to magic bytes.

```typescript
// ❌ INSECURE — No type check, original filename, web root storage
@Post('upload')
@UseInterceptors(FileInterceptor('file'))
uploadFile(@UploadedFile() file: Express.Multer.File) {
  fs.writeFileSync(`./public/${file.originalname}`, file.buffer);
}

// ✅ SECURE — Magic-byte validation + UUID filename + external storage
import { fileTypeFromBuffer } from 'file-type';
import { randomUUID } from 'crypto';
import * as path from 'path';

const ALLOWED_MIME_TYPES = new Set(['image/jpeg', 'image/png', 'image/webp', 'application/pdf']);
const MAX_FILE_SIZE = 5 * 1024 * 1024; // 5 MB

@Post('upload')
@UseInterceptors(
  FileInterceptor('file', {
    storage: memoryStorage(),
    limits: { fileSize: MAX_FILE_SIZE },
    fileFilter: (_req, file, cb) => {
      const ext = path.extname(file.originalname).toLowerCase();
      if (!['.jpg','.jpeg','.png','.webp','.pdf'].includes(ext)) {
        return cb(new BadRequestException('File extension not allowed'), false);
      }
      cb(null, true);
    },
  }),
)
async uploadFile(@UploadedFile() file: Express.Multer.File) {
  if (!file) throw new BadRequestException('No file uploaded');

  // Validate actual content (magic bytes)
  const detected = await fileTypeFromBuffer(file.buffer);
  if (!detected || !ALLOWED_MIME_TYPES.has(detected.mime)) {
    throw new BadRequestException('Invalid file type');
  }

  // Safe filename: UUID + validated extension
  const ext = detected.ext;
  const safeFilename = `${randomUUID()}.${ext}`;

  // Store outside web root (or upload to object storage)
  const uploadPath = path.join('/var/uploads', safeFilename);
  fs.writeFileSync(uploadPath, file.buffer);

  return { filename: safeFilename };
}

// Serve with Content-Disposition: attachment (never inline for untrusted types)
@Get('files/:filename')
async download(@Param('filename') filename: string, @Res() res: Response) {
  // Validate filename is a valid UUID.ext — prevent path traversal
  if (!/^[0-9a-f-]{36}\.(jpg|jpeg|png|webp|pdf)$/i.test(filename)) {
    throw new BadRequestException('Invalid filename');
  }
  const filePath = path.join('/var/uploads', filename);
  res.set('Content-Disposition', `attachment; filename="${filename}"`);
  res.sendFile(filePath);
}
```

---

## 12. HTTP Module SSRF

**Vulnerability:** `@nestjs/axios` (`HttpService`) with user-controlled URLs enables Server-Side Request Forgery (SSRF) — attackers can reach internal services, cloud metadata endpoints (`169.254.169.254`), and private network ranges not accessible from the internet.

**References:** CWE-918, OWASP API7:2023

### Mandatory Rules

- **Never pass user-supplied URLs directly** to `HttpService.get/post/request()`.
- **Validate URLs against a strict allowlist** of permitted hostnames/patterns before making outbound requests.
- **Block private IP ranges and metadata endpoints** — resolve the hostname and reject RFC 1918, RFC 5735, and link-local addresses.
- **Set explicit timeouts** on all `HttpService` calls — no default timeout means a slow target can exhaust connection pools.
- **Disable redirects** or validate redirect targets with the same allowlist.

```typescript
// ❌ INSECURE — User-controlled URL passed directly to HttpService
@Get('proxy')
async proxy(@Query('url') url: string) {
  const response = await this.httpService.get(url).toPromise();
  return response.data;
}

// ✅ SECURE — Hostname allowlist + private IP blocking
import { URL } from 'url';
import { isIP } from 'net';
import { lookup } from 'dns/promises';

const ALLOWED_HOSTS = new Set(['api.partner.com', 'webhooks.trusted.com']);
const PRIVATE_RANGES = [
  /^10\./,
  /^172\.(1[6-9]|2\d|3[01])\./,
  /^192\.168\./,
  /^127\./,
  /^169\.254\./,  // link-local / metadata
  /^::1$/,
  /^fc00:/i,
];

async function isSafeUrl(rawUrl: string): Promise<boolean> {
  let parsed: URL;
  try { parsed = new URL(rawUrl); } catch { return false; }

  if (!['https:'].includes(parsed.protocol)) return false;
  if (!ALLOWED_HOSTS.has(parsed.hostname)) return false;

  // Resolve and check IP to prevent DNS rebinding
  const addresses = await lookup(parsed.hostname, { all: true }).catch(() => []);
  for (const { address } of addresses) {
    if (PRIVATE_RANGES.some((re) => re.test(address))) return false;
  }
  return true;
}

@Get('webhook-test')
async testWebhook(@Query('callbackUrl') url: string) {
  if (!(await isSafeUrl(url))) throw new BadRequestException('URL not allowed');
  return this.httpService
    .get(url, {
      timeout: 5000,
      maxRedirects: 0,     // prevent open redirect chains
      validateStatus: () => true,
    })
    .toPromise();
}
```

---

## 13. ClassSerializerInterceptor & Sensitive Field Exposure

**Vulnerability:** Returning TypeORM/Prisma entities directly from controllers exposes all fields — including `passwordHash`, `resetToken`, `isAdmin`, and internal IDs. The `ClassSerializerInterceptor` only excludes `@Exclude()` fields when `plainToInstance` is applied; returning plain objects bypasses it.

**References:** CWE-200, CWE-312, OWASP API3:2023

### Mandatory Rules

- **Register `ClassSerializerInterceptor` globally** as `APP_INTERCEPTOR` and use `@Exclude()` on sensitive entity fields.
- **Return DTO/Response class instances** from service methods, not raw entity objects — `ClassSerializerInterceptor` only works on class instances.
- **Use `@Expose()` allowlist strategy** — decorate only safe fields rather than trying to exclude each sensitive one.
- **Never return ORM entities directly** from controller methods — always map to response DTOs.

```typescript
// ❌ INSECURE — Raw entity returned; passwordHash exposed in JSON response
@Get('users/:id')
async getUser(@Param('id') id: number) {
  return this.usersRepository.findOne({ where: { id } }); // includes passwordHash
}

// ✅ SECURE — @Exclude() on entity + global ClassSerializerInterceptor
// user.entity.ts
import { Exclude, Expose } from 'class-transformer';

@Entity()
export class User {
  @Expose() id: number;
  @Expose() email: string;
  @Expose() createdAt: Date;

  @Exclude()
  passwordHash: string;

  @Exclude()
  resetToken: string;

  @Exclude()
  twoFactorSecret: string;
}

// app.module.ts
providers: [
  { provide: APP_INTERCEPTOR, useClass: ClassSerializerInterceptor },
]

// Or use explicit response DTO mapping in service layer:
// user-response.dto.ts
export class UserResponseDto {
  constructor(user: User) {
    this.id = user.id;
    this.email = user.email;
    this.createdAt = user.createdAt;
    // passwordHash intentionally omitted
  }
  id: number;
  email: string;
  createdAt: Date;
}

@Get('users/:id')
async getUser(@Param('id', ParseIntPipe) id: number) {
  const user = await this.usersService.findOne(id);
  return new UserResponseDto(user); // only safe fields
}
```

---

## 14. WebSocket Security

**Vulnerability:** NestJS WebSocket gateways do not apply HTTP Guards by default — the standard `JwtAuthGuard` does not run for WebSocket connections. Without explicit `WsGuard`, all WebSocket connections and messages are unauthenticated.

**References:** CWE-284, CWE-862, OWASP API2:2023

### Mandatory Rules

- **Implement a `WsGuard`** that validates JWT from the WebSocket handshake headers or query string — HTTP Guards do not apply to WebSocket events.
- **Validate message payloads** in WebSocket handlers with the same `ValidationPipe` used for HTTP.
- **Rate-limit WebSocket messages** at the gateway level to prevent message flooding.
- **Use namespace-level authentication** — require auth before joining a room, not just at connection time.

```typescript
// ❌ INSECURE — No auth on WebSocket gateway; all connections accepted
@WebSocketGateway()
export class ChatGateway {
  @SubscribeMessage('message')
  handleMessage(client: Socket, payload: any) {
    this.server.emit('message', payload); // unauthenticated broadcast
  }
}

// ✅ SECURE — JWT-authenticated WebSocket gateway
@Injectable()
export class WsJwtGuard implements CanActivate {
  constructor(private jwtService: JwtService, private config: ConfigService) {}

  async canActivate(context: ExecutionContext): Promise<boolean> {
    const client: Socket = context.switchToWs().getClient();
    const token =
      client.handshake.auth?.token ??
      client.handshake.headers?.authorization?.split(' ')[1];

    if (!token) {
      client.disconnect();
      return false;
    }

    try {
      const payload = this.jwtService.verify(token, {
        secret: this.config.getOrThrow('JWT_SECRET'),
        algorithms: ['HS256'],
        issuer: this.config.getOrThrow('JWT_ISSUER'),
      });
      client.data.user = payload;
      return true;
    } catch {
      client.disconnect();
      return false;
    }
  }
}

@UseGuards(WsJwtGuard)
@WebSocketGateway({ namespace: '/chat', cors: { origin: ['https://app.example.com'] } })
export class ChatGateway {
  @SubscribeMessage('message')
  handleMessage(
    @ConnectedSocket() client: Socket,
    @MessageBody(new ValidationPipe({ whitelist: true })) payload: ChatMessageDto,
  ) {
    // client.data.user is the verified JWT payload
    this.server.to(payload.roomId).emit('message', {
      text: payload.text,
      userId: client.data.user.sub,
    });
  }
}
```

---

## 15. Microservice Transport Security

**Vulnerability:** NestJS microservices using TCP transport transmit data in plaintext. Redis transport without authentication exposes internal messages to anyone with Redis access. RabbitMQ without TLS and credentials allows message injection and eavesdropping.

**References:** CWE-319, CWE-306, OWASP API8:2023

### Mandatory Rules

- **Never use TCP microservice transport in production** without TLS — all messages are plaintext.
- **Configure Redis transport with authentication** (`auth` option) and TLS when Redis is not on a private network.
- **Use RabbitMQ with TLS (`amqps://`)** and credential authentication — never `amqp://guest:guest@`.
- **Validate all incoming microservice message payloads** with `ValidationPipe` — external message queues can be injected by attackers who gain queue access.
- **Apply rate limiting and circuit breakers** on microservice clients to prevent cascading failures.

```typescript
// ❌ INSECURE — Plaintext TCP with no auth
ClientsModule.register([{
  name: 'ORDERS_SERVICE',
  transport: Transport.TCP,
  options: { host: 'orders-service', port: 3001 },
}])

// ❌ INSECURE — Redis without auth
ClientsModule.register([{
  name: 'NOTIFICATIONS_SERVICE',
  transport: Transport.REDIS,
  options: { host: 'redis', port: 6379 }, // no password
}])

// ✅ SECURE — RabbitMQ with TLS and credentials
ClientsModule.registerAsync([{
  name: 'ORDERS_SERVICE',
  imports: [ConfigModule],
  inject: [ConfigService],
  useFactory: (config: ConfigService) => ({
    transport: Transport.RMQ,
    options: {
      urls: [config.getOrThrow<string>('RABBITMQ_URL')], // amqps://user:pass@host/vhost
      queue: 'orders_queue',
      queueOptions: { durable: true },
      socketOptions: {
        heartbeatIntervalInSeconds: 60,
        reconnectTimeInSeconds: 5,
      },
    },
  }),
}])

// ✅ SECURE — Validate incoming microservice messages
@MessagePattern('create_order')
async createOrder(
  @Payload(new ValidationPipe({ whitelist: true, forbidNonWhitelisted: true }))
  data: CreateOrderDto,
) {
  return this.ordersService.create(data);
}
```

---

## 16. GraphQL Security

**Vulnerability:** `@nestjs/graphql` without query depth limiting, query complexity analysis, or introspection disabled in production enables DoS via deeply nested queries, resource exhaustion via overly complex queries, and schema disclosure via introspection.

**References:** CWE-400, CWE-200, OWASP API4:2023

### Mandatory Rules

- **Disable introspection in production** — set `introspection: process.env.NODE_ENV !== 'production'`.
- **Apply query depth limiting** with `graphql-depth-limit` — maximum depth of 5–7 for most APIs.
- **Apply query complexity analysis** with `graphql-query-complexity` — reject queries exceeding a complexity budget.
- **Use `@UseGuards()` on GraphQL resolvers** — NestJS applies HTTP Guards to GraphQL queries/mutations when using the `GqlExecutionContext`.
- **Validate all resolver arguments** with `ValidationPipe` — `@Args()` values are user-controlled.
- **Never expose internal error details** — use `formatError` to strip stack traces from GraphQL error responses.

```typescript
// ❌ INSECURE — GraphQL with introspection, no depth limit, no auth
GraphQLModule.forRoot<ApolloDriverConfig>({
  driver: ApolloDriver,
  autoSchemaFile: true,
})

// ✅ SECURE — Hardened GraphQL module
import depthLimit from 'graphql-depth-limit';
import { createComplexityLimitRule } from 'graphql-validation-complexity';

GraphQLModule.forRoot<ApolloDriverConfig>({
  driver: ApolloDriver,
  autoSchemaFile: true,
  introspection: process.env.NODE_ENV !== 'production',
  playground: process.env.NODE_ENV !== 'production',
  validationRules: [
    depthLimit(7),
    createComplexityLimitRule(1000, {
      onCost: (cost) => console.log('Query cost:', cost),
    }),
  ],
  formatError: (error) => ({
    message: error.message,
    code: error.extensions?.code,
    // strip: locations, path, extensions.exception (stack trace)
  }),
})

// ✅ SECURE — Auth guard on GraphQL resolver
@UseGuards(JwtAuthGuard)
@Resolver(() => User)
export class UsersResolver {
  @Query(() => User)
  async me(@CurrentUser() user: User) {
    return user;
  }

  @Mutation(() => Post)
  async createPost(
    @Args('input') input: CreatePostInput, // validated by ValidationPipe
    @CurrentUser() user: User,
  ) {
    return this.postsService.create(user.id, input);
  }
}
```

---

## 17. Error Handling & Information Disclosure

**Vulnerability:** NestJS's default exception filter exposes stack traces, internal error messages, TypeORM query errors, and validation details in production responses — revealing database schema, file paths, and internal architecture.

**References:** CWE-209, CWE-497

### Mandatory Rules

- **Implement a global custom `ExceptionFilter`** that maps all unhandled exceptions to safe, generic error responses in production.
- **Never expose `exception.stack`, SQL error messages, or TypeORM/Prisma error details** in HTTP responses.
- **Log full error details server-side** using structured logging — only return a correlation ID to the client.
- **Map database errors to generic responses** — e.g., unique constraint violations should return `409 Conflict`, not the full SQL error.

```typescript
// ❌ INSECURE — Default NestJS behavior exposes internal errors
// TypeORM throws: QueryFailedError: duplicate key value violates unique constraint
// NestJS 500 response body: { statusCode: 500, message: "Internal server error" }
// but if using development mode, stack trace is included

// ❌ INSECURE — Manually re-throwing with internal details
@Catch()
export class AllExceptionsFilter implements ExceptionFilter {
  catch(exception: unknown, host: ArgumentsHost) {
    const res = host.switchToHttp().getResponse<Response>();
    res.status(500).json({ error: exception.toString(), stack: (exception as Error).stack });
  }
}

// ✅ SECURE — Global exception filter with safe responses
import { QueryFailedError } from 'typeorm';
import { randomUUID } from 'crypto';

@Catch()
export class GlobalExceptionFilter implements ExceptionFilter {
  private readonly logger = new Logger(GlobalExceptionFilter.name);

  catch(exception: unknown, host: ArgumentsHost) {
    const ctx = host.switchToHttp();
    const res = ctx.getResponse<Response>();
    const req = ctx.getRequest<Request>();
    const correlationId = randomUUID();

    // Log full details server-side
    this.logger.error({
      correlationId,
      message: (exception as Error)?.message,
      stack: (exception as Error)?.stack,
      path: req.url,
    });

    if (exception instanceof HttpException) {
      const status = exception.getStatus();
      const body = exception.getResponse();
      return res.status(status).json(
        typeof body === 'string' ? { message: body, correlationId } : { ...body as object, correlationId }
      );
    }

    // Map database errors to safe responses
    if (exception instanceof QueryFailedError) {
      const pgCode = (exception as any).code;
      if (pgCode === '23505') { // unique violation
        return res.status(409).json({ message: 'Resource already exists', correlationId });
      }
    }

    // Generic fallback
    return res.status(500).json({
      message: 'An unexpected error occurred',
      correlationId, // client can report this for support
    });
  }
}

// Register globally
app.useGlobalFilters(new GlobalExceptionFilter());
```

---

## CVE Reference Table

| CVE | Severity | Component | Description | Fixed In |
|-----|----------|-----------|-------------|----------|
| CVE-2022-21190 | Critical (9.8) | class-transformer ≤0.5.0 | Prototype pollution via `plainToClass`/`plainToInstance` with `__proto__` key in untrusted input | 0.5.1 |
| CVE-2023-26108 | High (7.5) | class-transformer ≤0.5.1 | ReDoS in string-to-boolean transformation regex | 0.5.2 |
| CVE-2023-26115 | High (7.5) | class-validator ≤0.13.4 | ReDoS via `@IsUrl()` decorator on specially crafted input | 0.14.0 |
| CVE-2022-23529 | High (7.6) | jsonwebtoken ≤8.5.1 | Arbitrary file read when `secretOrPublicKey` is a path string; allows `alg:none` if not explicitly constrained | 9.0.0 |
| CVE-2024-29415 | Critical (9.8) | ip ≤2.0.0 | `isPublic()` incorrectly classifies `::ffff:127.x.x.x` IPv4-mapped IPv6 as public — SSRF bypass in IP validation | 2.0.1 |
| CVE-2022-24999 | High (7.5) | qs ≤6.10.2 | Prototype pollution via `__proto__` in parsed query string | 6.10.3 |
| CVE-2023-28155 | Medium (6.1) | @fastify/reply-from | SSRF via header injection when NestJS uses Fastify adapter with reply-from proxy | 9.4.1 |
| CVE-2024-21488 | High (7.5) | network-interface | Command injection via network interface name — affects NestJS apps using network utilities | patched |
| CVE-2023-45857 | Medium (6.5) | axios ≤1.5.1 | XSRF-TOKEN header leaked to third-party origins via HTTP redirects in `@nestjs/axios` | 1.6.0 |
| CVE-2025-27789 | High (7.4) | TypeORM ≤0.3.20 | SQL injection via `order` clause when using `find()` with user-controlled sort fields | 0.3.21 |

---

## Security Checklist

### Foundation
- [ ] `ValidationPipe` registered globally with `whitelist: true`, `forbidNonWhitelisted: true`, `transform: true`
- [ ] `JwtAuthGuard` registered as `APP_GUARD`; public routes use explicit `@Public()` decorator
- [ ] `ThrottlerGuard` registered as `APP_GUARD` with Redis storage in production
- [ ] `ClassSerializerInterceptor` registered as `APP_INTERCEPTOR`; sensitive entity fields annotated with `@Exclude()`
- [ ] Global `ExceptionFilter` strips stack traces and database errors from responses
- [ ] `helmet()` applied as first middleware with custom CSP
- [ ] CORS configured with explicit origin allowlist — no `origin: true` or `*` with credentials

### Authentication & Authorization
- [ ] `JwtStrategy` specifies `algorithms: ['HS256']` (or RS256 with JWKS) — rejects `alg:none`
- [ ] JWT secret sourced from `ConfigService.getOrThrow()` — not hardcoded
- [ ] JWT `issuer` and `audience` validated on every token
- [ ] `ignoreExpiration: false` (default) in Passport JWT strategy
- [ ] Refresh token rotation implemented; refresh tokens stored hashed in database
- [ ] `RolesGuard` enforces RBAC; resource ownership checked for user-owned data (ABAC)
- [ ] Sensitive operations re-verify roles against database (not only JWT payload)

### Input Validation & Mass Assignment
- [ ] All DTOs use `class-validator` decorators — no untyped `any` in request handlers
- [ ] `class-transformer` ≥ 0.5.1, `class-validator` ≥ 0.14.0 pinned in `package.json`
- [ ] `@Matches()` regex patterns use bounded quantifiers — no catastrophic backtracking
- [ ] `@MaxLength()` applied before `@Matches()` to bound ReDoS exposure
- [ ] No `plainToInstance` on deeply nested untrusted objects without depth limits

### Database
- [ ] TypeORM raw `.query()` uses parameterized placeholders — no string interpolation
- [ ] `createQueryBuilder()` uses `.setParameter()` for all user values
- [ ] Prisma `$queryRaw` uses Prisma.sql tagged templates — no `Prisma.raw()` with user input
- [ ] TypeORM `logging: false` (or filtered) in production
- [ ] CVE-2025-27789: TypeORM `find()` with user-controlled sort fields validated against allowlist

### File Uploads
- [ ] `memoryStorage()` used — files validated before disk write
- [ ] File type validated with `file-type` magic bytes — not `mimetype` header
- [ ] Maximum file size enforced via `limits.fileSize`
- [ ] Uploaded files saved with UUID filenames — never original filename
- [ ] Upload directory outside web root; served with `Content-Disposition: attachment`

### WebSockets & Microservices
- [ ] WebSocket gateways use `WsGuard` for authentication — HTTP Guards do not apply
- [ ] WebSocket message payloads validated with `ValidationPipe`
- [ ] Microservice transport uses TLS (RabbitMQ `amqps://`, Redis with TLS)
- [ ] Microservice message payloads validated with `ValidationPipe`
- [ ] TCP transport not used in production without TLS

### GraphQL
- [ ] Introspection disabled in production (`introspection: process.env.NODE_ENV !== 'production'`)
- [ ] Query depth limit configured (`graphql-depth-limit`, max 7)
- [ ] Query complexity budget enforced (`graphql-query-complexity`)
- [ ] `formatError` strips stack traces and internal details
- [ ] Resolver arguments validated via `ValidationPipe`

### Configuration & Secrets
- [ ] `ConfigModule` validates all required env vars with Joi/Zod at startup
- [ ] All secret access uses `ConfigService.getOrThrow()` — fails fast if missing
- [ ] No config/env dump endpoints in production
- [ ] Secrets not logged by any `Logger` call

### Supply Chain
- [ ] `npm audit` / `pnpm audit` runs in CI — build fails on Critical/High
- [ ] `package-lock.json` or `pnpm-lock.yaml` committed and verified
- [ ] `class-transformer`, `class-validator`, `jsonwebtoken`, `qs` pinned to patched versions
- [ ] `axios` ≥ 1.6.0 to prevent XSRF header leakage (CVE-2023-45857)

---

## Tooling

| Tool | Purpose | Command |
|------|---------|---------|
| [npm audit](https://docs.npmjs.com/cli/audit) | Dependency vulnerability scanning | `npm audit --audit-level=high` |
| [Snyk](https://snyk.io) | Advanced dependency + code scanning | `snyk test && snyk code test` |
| [ESLint + @typescript-eslint](https://typescript-eslint.io) | Static analysis for TypeScript | `eslint . --ext .ts` |
| [eslint-plugin-security](https://github.com/eslint-community/eslint-plugin-security) | Node.js security rules (RegExp injection, eval, etc.) | Add to `.eslintrc` |
| [Semgrep](https://semgrep.dev) | Custom security pattern matching | `semgrep --config=p/typescript` |
| [OWASP Dependency-Check](https://owasp.org/www-project-dependency-check/) | CVE scanning for npm dependencies | `dependency-check --project nestjs-app --scan .` |
| [artillery](https://www.artillery.io) | Load/rate-limit testing | `artillery run rate-limit-test.yml` |
| [jest-cucumber](https://github.com/nicholasgasior/jest-cucumber) | BDD security scenario testing | `jest --testPathPattern=security` |
| [Helmet](https://helmetjs.github.io) | HTTP security headers | `npm install helmet` |
| [graphql-depth-limit](https://github.com/stems/graphql-depth-limit) | Prevent deeply nested GraphQL queries | `npm install graphql-depth-limit` |
| [graphql-query-complexity](https://github.com/slicknode/graphql-query-complexity) | GraphQL query cost analysis | `npm install graphql-query-complexity` |
| [nestjs-pino](https://github.com/iamolegga/nestjs-pino) | Structured logging with redaction | `npm install nestjs-pino pino-http` |
