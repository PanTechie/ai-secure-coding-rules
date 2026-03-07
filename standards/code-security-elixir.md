# 💧 Elixir Security Rules

> **Standard:** Security rules for Elixir 1.15+ and Phoenix 1.7+, covering language-level risks, OTP/Erlang VM pitfalls, and the Phoenix web framework.
> **Sources:** Elixir Security Advisories, Erlang/OTP Security Advisories, NIST NVD, Sobelow (Phoenix Security Scanner), OWASP, HackerOne disclosures, CVE Details
> **Version:** 1.0.0
> **Last updated:** March 2026
> **Scope:** Elixir 1.15+ runtime, OTP 26+, Phoenix 1.7+, Ecto 3.x, Plug, LiveView. Does not cover Nerves (embedded) or distributed Erlang cluster security in depth.

---

## General Instructions

Apply these rules when writing or reviewing Elixir and Phoenix code. Elixir inherits both the power and the dangers of the Erlang VM (BEAM): `Code.eval_string/2`, `:erlang.binary_to_term/1`, and `EEx.eval_string/2` all enable code execution from untrusted data. The most critical Elixir-specific risks that do not exist in most other languages are **atom exhaustion** (`String.to_atom/1` with user input causes unbounded atom table growth and VM crash) and **ETF deserialization RCE** (`:erlang.binary_to_term/1` without `[:safe]` flag). Pay special attention to secrets leaking at compile time via `config.exs` vs `runtime.exs`, and to Erlang/OTP SSH and TLS vulnerabilities that affect any Elixir application running on an unpatched OTP version.

---

## 1. Code Injection (eval and EEx Templates)

**Vulnerability:** `Code.eval_string/2`, `Code.eval_file/2`, `Code.compile_string/2`, and `EEx.eval_string/2` execute arbitrary Elixir code at runtime. Passing user-controlled input to any of these functions enables full RCE. `:erlang.apply/3` with user-controlled module or function atoms is equally dangerous.

**References:** CWE-94, CWE-95, OWASP Code Injection

### Mandatory Rules

- **Never pass user input to `Code.eval_string/2`, `Code.eval_file/2`, or `Code.compile_string/2`** — all evaluate arbitrary Elixir and enable RCE.
- **Never pass user input to `EEx.eval_string/2` or `EEx.eval_file/2`** — EEx templates execute embedded Elixir code (`<%= ... %>`); use pre-compiled, static template files only.
- **Never use `:erlang.apply/3` with user-controlled module or function atoms** — enables calling any BIF or loaded module function.
- **Use `Phoenix.Template` compiled templates** — compile templates at build time, never at runtime with user data.
- **Avoid `Macro.expand/2` on user-supplied ASTs** — AST manipulation with untrusted input can lead to unexpected code paths.

```elixir
# ❌ INSECURE — Code.eval_string with user input: RCE
Code.eval_string(params["expression"])

# ❌ INSECURE — EEx template from user input: RCE
EEx.eval_string(params["template"], assigns: assigns)

# ❌ INSECURE — :erlang.apply with user-controlled atoms
module = String.to_atom(params["module"])
:erlang.apply(module, :run, [args])

# ✅ SECURE — static compiled template (Phoenix)
Phoenix.View.render(MyAppWeb.PageView, "index.html", assigns)

# ✅ SECURE — allowlist for dynamic dispatch
@allowed_modules %{"report" => MyApp.Reports, "export" => MyApp.Exports}
module = Map.fetch!(@allowed_modules, params["action"])  # raises if not found
module.run(args)
```

---

## 2. Atom Exhaustion (String.to_atom)

**Vulnerability:** Elixir atoms are never garbage collected — the atom table has a fixed limit (default: 1,048,576). Calling `String.to_atom/1` with user-supplied strings creates new atoms indefinitely until the VM crashes with `system_limit`, causing a denial-of-service condition.

**References:** CWE-400, Erlang atom exhaustion DoS, OWASP DoS

### Mandatory Rules

- **Never call `String.to_atom/1` with user-supplied strings** — use `String.to_existing_atom/1` which only succeeds for already-defined atoms, or keep the value as a string.
- **Never call `:erlang.list_to_atom/1` or `:erlang.binary_to_atom/2` with untrusted data** without the `:latin1` encoding and pre-existence check.
- **Use `String.to_existing_atom/1` wrapped in a `try/rescue`** when converting external values to atoms that must exist.
- **Prefer maps with string keys** for external data rather than converting to atom keys.
- **Avoid `Map.new(params, fn {k, v} -> {String.to_atom(k), v} end)`** on user-supplied maps — converts every key to a new atom.

```elixir
# ❌ INSECURE — atom exhaustion: each unique request string creates a new atom
action = String.to_atom(conn.params["action"])

# ❌ INSECURE — converts all user-supplied map keys to atoms
opts = Enum.into(params, %{}, fn {k, v} -> {String.to_atom(k), v} end)

# ✅ SECURE — only succeeds for pre-existing atoms; raises ArgumentError otherwise
action =
  try do
    String.to_existing_atom(conn.params["action"])
  rescue
    ArgumentError -> :unknown
  end

# ✅ SECURE — keep user data as strings; convert to atoms only at defined boundaries
def handle_action("report", params), do: MyApp.Reports.run(params)
def handle_action("export", params), do: MyApp.Exports.run(params)
def handle_action(_, _), do: {:error, :unknown_action}
```

---

## 3. Binary/Term Deserialization (:erlang.binary_to_term)

**Vulnerability:** `:erlang.binary_to_term/1` deserializes the Erlang External Term Format (ETF). A crafted ETF payload can create arbitrary atoms, reference internal modules, and in some OTP configurations trigger code loading. Without the `[:safe]` option, it additionally allows atom creation that contributes to atom exhaustion and can trigger side effects in custom `__struct__` implementations.

**References:** CWE-502, Erlang binary_to_term security notes, multiple ETF deserialization PoCs

### Mandatory Rules

- **Never call `:erlang.binary_to_term/1` on untrusted data without the `[:safe]` flag** — use `:erlang.binary_to_term(data, [:safe])` which prevents new atom creation.
- **Prefer JSON, MessagePack, or Protobuf for external data exchange** — avoid ETF for inter-service or client communication entirely.
- **Verify message sources in distributed Erlang** — cookie-based authentication is the only protection; never expose the Erlang port (4369/epmd or custom) to the internet.
- **Treat `:erlang.term_to_binary/1` output as sensitive** — it encodes the full internal structure of Elixir/Erlang terms; do not leak it to clients.
- **Never deserialize Phoenix channel messages** into structs without validating the schema first.

```elixir
# ❌ INSECURE — binary_to_term without :safe: atom creation + potential RCE gadgets
data = :erlang.binary_to_term(received_bytes)

# ✅ SECURE — [:safe] flag prevents new atom creation
data = :erlang.binary_to_term(received_bytes, [:safe])

# ✅ SECURE — use Jason (JSON) for external data instead of ETF
{:ok, data} = Jason.decode(received_json)

# ✅ SECURE — validate struct shape after safe deserialization
with {:ok, %{"type" => "event", "payload" => payload}} <- Jason.decode(body),
     {:ok, event} <- MyApp.Event.validate(payload) do
  handle_event(event)
end
```

---

## 4. SQL Injection (Ecto)

**Vulnerability:** Ecto's query DSL is parameterized by default, but `Ecto.Query.fragment/1`, `Repo.query/2` with string interpolation, and `Repo.query!/2` allow raw SQL that bypasses parameterization. Dynamic `ORDER BY` and `GROUP BY` clauses are common injection points.

**References:** CWE-89, OWASP SQL Injection, Ecto Security documentation

### Mandatory Rules

- **Never interpolate user input into `Ecto.Query.fragment/1`** — use `fragment("col = ?", value)` with explicit binding instead.
- **Never build raw SQL strings with user input for `Repo.query/2`** — always use parameterized form `Repo.query("SELECT ... WHERE col = $1", [value])`.
- **Validate dynamic `ORDER BY` column names against an allowlist** before interpolating into fragments.
- **Use Ecto's composable query DSL** (`where`, `order_by`, `limit`) instead of raw SQL wherever possible — it parameterizes automatically.
- **Never use `^` (pin operator) with raw user strings in Ecto `where` expressions** — `^params["role"]` inserts the value safely, but ensure it's not used in column name position.

```elixir
# ❌ INSECURE — fragment with string interpolation: SQL injection
col = params["sort_col"]
from(u in User, order_by: fragment("? DESC", ^col))
# ^col still goes through parameterization for VALUES, but not for identifiers

# ❌ INSECURE — raw SQL with string interpolation
Repo.query("SELECT * FROM users WHERE email = '#{params["email"]}'")

# ✅ SECURE — Ecto composable query with pin operator for values
from(u in User, where: u.email == ^params["email"])

# ✅ SECURE — validated allowlist for dynamic ORDER BY
@allowed_sort_cols ~w[name inserted_at email]a

def sort_col(col) when col in @allowed_sort_cols, do: col
def sort_col(_), do: :inserted_at

from(u in User, order_by: [{:asc, ^sort_col(params["sort"])}])

# ✅ SECURE — parameterized raw query
Repo.query("SELECT * FROM users WHERE email = $1", [params["email"]])
```

---

## 5. Command Injection

**Vulnerability:** `:os.cmd/1` passes a single binary string to the shell, enabling full shell injection. `System.cmd/3` is safer when used with a list of arguments, but vulnerable when the command itself is user-controlled. `Port.open/2` with `{:spawn, cmd_string}` is equivalent to `:os.cmd`.

**References:** CWE-78, OWASP Command Injection

### Mandatory Rules

- **Never use `:os.cmd/1` with user-supplied data** — it always invokes a shell; there is no safe parameterized form.
- **Use `System.cmd/3` with a separate argument list**, never with a single shell string: `System.cmd("convert", [arg1, arg2])`.
- **Validate and allowlist any user-controlled values** used as arguments to `System.cmd/3` — argument injection is still possible even without a shell.
- **Never use `Port.open({:spawn, user_input}, ...)` or `Port.open({:spawn_executable, user_path}, ...)`** with untrusted paths.
- **Prefer Elixir/OTP libraries over shelling out** — use `Image` (libvips binding), `ex_aws`, `NimbleCSV`, etc. instead of external commands.

```elixir
# ❌ INSECURE — :os.cmd passes to shell: command injection
:os.cmd(~c"convert #{filename} output.png")

# ❌ INSECURE — System.cmd with shell string
System.cmd("sh", ["-c", "convert #{filename} output.png"])

# ❌ INSECURE — Port.open with user-controlled spawn
Port.open({:spawn, "process " <> params["input"]}, [:binary])

# ✅ SECURE — System.cmd with argument list (no shell invoked)
{output, 0} = System.cmd("convert", [filename, "output.png"])

# ✅ SECURE — validate filename before use
defp safe_filename!(name) do
  if String.match?(name, ~r/\A[\w\-]+\.(jpg|png|gif)\z/) do
    name
  else
    raise ArgumentError, "Invalid filename"
  end
end

{_, 0} = System.cmd("convert", [safe_filename!(params["file"]), "output.png"])
```

---

## 6. Path Traversal and File Operations

**Vulnerability:** Constructing file paths from user input enables directory traversal. `File.read/1`, `File.stream!/1`, `Path.expand/1`, and `File.open/2` are common sinks. Phoenix's `send_file/3` and `send_download/3` can serve arbitrary files if the path is not bounded.

**References:** CWE-22, OWASP Path Traversal

### Mandatory Rules

- **Canonicalize file paths with `Path.expand/1`** and verify the result starts with the allowed base directory.
- **Use `Path.safe_relative/2`** (Elixir 1.14+) to validate that a path is relative and does not escape its base.
- **Never construct paths by string concatenation with user input** — use `Path.join/2` with a fixed base directory and a sanitized filename.
- **Strip directory components from user filenames** with `Path.basename/1` before joining.
- **Use UUIDs for stored file names** — never use original user-supplied filenames on disk.

```elixir
# ❌ INSECURE — path traversal: ../../../../etc/passwd
File.read("uploads/" <> params["filename"])

# ❌ INSECURE — Path.join doesn't prevent traversal if component starts with /
Path.join("/var/uploads", params["filename"])  # "/var/uploads" is ignored if filename starts with /

# ✅ SECURE — canonicalize and verify prefix
@base_dir Path.expand("priv/static/uploads")

def safe_path!(filename) do
  name     = Path.basename(filename)
  expanded = Path.expand(Path.join(@base_dir, name))

  unless String.starts_with?(expanded, @base_dir) do
    raise ArgumentError, "Path traversal detected"
  end

  expanded
end

content = File.read!(safe_path!(params["filename"]))

# ✅ SECURE — Elixir 1.14+ Path.safe_relative
case Path.safe_relative(params["filename"], @base_dir) do
  {:ok, safe} -> File.read!(safe)
  :error      -> {:error, :forbidden}
end
```

---

## 7. XML/XXE — Xmerl and SweetXml

**Vulnerability:** Erlang's built-in `xmerl` XML parser resolves external entities by default, enabling XXE attacks — file read, SSRF, and denial-of-service. `SweetXml` (which wraps `xmerl`) inherits this behavior. `Saxy` is a pure-Elixir SAX parser that does not resolve external entities.

**References:** CWE-611, OWASP XXE Prevention

### Mandatory Rules

- **Disable external entity resolution when using `xmerl`** by setting `allow_entities: false` and custom entity handler.
- **Use `Saxy` instead of `xmerl`/`SweetXml` for parsing untrusted XML** — it does not support external entity resolution by design.
- **Never parse user-supplied XML with `SweetXml.parse/2` using default options** — it resolves external entities via `xmerl`.
- **If `SweetXml` is required**, wrap with an entity-disabling option or use `Saxy` for the initial parse and `SweetXml` only on trusted data.

```elixir
# ❌ INSECURE — SweetXml with default xmerl: XXE possible
import SweetXml
doc = parse(user_xml)
result = doc |> xpath(~x"//user/name/text()")

# ❌ INSECURE — xmerl default parse resolves external entities
:xmerl_scan.string(String.to_charlist(user_xml))

# ✅ SECURE — Saxy: no external entity resolution
{:ok, parsed} = Saxy.parse_string(user_xml, MyApp.SaxHandler, [])

# ✅ SECURE — xmerl with external entity hook that rejects all external entities
defp safe_xml_opts do
  [
    fetch_fun: fn _uri, _fetcher_opts -> {:error, :not_allowed} end,
    rules: {fn _, _, _ -> :undefined end, fn _ -> nil end, []}
  ]
end

:xmerl_scan.string(String.to_charlist(user_xml), safe_xml_opts())
```

---

## 8. Cryptography

**Vulnerability:** Elixir's `:crypto` module wraps OpenSSL — correct usage requires explicit mode selection, unique IVs, and authentication tags. Common mistakes: using AES-CBC without MAC, reusing IVs, using MD5/SHA1 for passwords, and generating tokens with `:rand` instead of `:crypto.strong_rand_bytes/1`.

**References:** CWE-327, CWE-328, CWE-330, OWASP Cryptographic Failures

### Mandatory Rules

- **Use `Bcrypt.hash_pwd_salt/2` (bcrypt_elixir) or `Argon2.hash_pwd_salt/2` (argon2_elixir) for password hashing** — never `:crypto.hash(:sha256, password)` or MD5.
- **Use AES-256-GCM for symmetric encryption** — `:crypto.crypto_one_time_aead(:aes_256_gcm, key, iv, plaintext, aad, true)` — includes authentication.
- **Generate a unique 12-byte IV per encryption** with `:crypto.strong_rand_bytes(12)` — never hardcode or reuse.
- **Generate tokens with `:crypto.strong_rand_bytes/1` or `Phoenix.Token.sign/4`** — never `:rand.uniform/1` or `:erlang.unique_integer/1`.
- **Use `:crypto.hash_equals/2`** (OTP 25+) or a constant-time comparison for HMAC/token verification — prevents timing attacks.
- **Verify GCM authentication tag** on decryption — `:crypto.crypto_one_time_aead/6` raises `CryptoError` on tag mismatch; do not catch it silently.

```elixir
# ❌ INSECURE — SHA-256 for password: GPU-crackable
:crypto.hash(:sha256, password) |> Base.encode16()

# ❌ INSECURE — AES-CBC without MAC: vulnerable to padding oracle
:crypto.block_encrypt(:aes_cbc256, key, iv, plaintext)

# ❌ INSECURE — weak token generation
token = :rand.uniform(10_000_000) |> Integer.to_string()

# ✅ SECURE — Bcrypt for passwords
hashed = Bcrypt.hash_pwd_salt(password)
Bcrypt.verify_pass(password, hashed)  # verification

# ✅ SECURE — AES-256-GCM encryption
key = :crypto.strong_rand_bytes(32)
iv  = :crypto.strong_rand_bytes(12)
{ciphertext, tag} = :crypto.crypto_one_time_aead(:aes_256_gcm, key, iv, plaintext, "", true)
# Store: iv <> tag <> ciphertext

# ✅ SECURE — GCM decryption (raises on tag mismatch)
plaintext = :crypto.crypto_one_time_aead(:aes_256_gcm, key, iv, ciphertext, "", tag, false)

# ✅ SECURE — cryptographically strong token
token = :crypto.strong_rand_bytes(32) |> Base.url_encode64(padding: false)
```

---

## 9. Authentication — Guardian and Pow

**Vulnerability:** Guardian JWT misconfiguration (weak secret, algorithm confusion, missing claim validation), Pow session misconfiguration, and insecure token storage are common authentication weaknesses in Phoenix applications.

**References:** CWE-287, CWE-347, CWE-384, OWASP Authentication Failures

### Mandatory Rules

- **Store Guardian `secret_key` in runtime configuration** (`config/runtime.exs`) not `config.exs` — compile-time secrets are embedded in releases and extractable from the binary.
- **Set `ttl` on all Guardian tokens** — short-lived access tokens (15 min) with refresh tokens; never omit expiry.
- **Validate all JWT claims**: `iss`, `aud`, `exp`, `iat` — reject tokens with unexpected values.
- **Reject the `"none"` algorithm** — ensure Guardian's allowed algorithms list is explicit: `allowed_algos: ["HS512"]` or `["RS256"]`.
- **Use `Pow.Plug.authenticate_user/2`** with `Bcrypt` — never compare passwords directly with `==`.
- **Regenerate session on login** — call `configure_session(conn, renew: true)` in Phoenix before setting session data to prevent session fixation.
- **Set session cookie attributes** — `secure: true`, `http_only: true`, `same_site: "Lax"` in `endpoint.ex`.

```elixir
# ❌ INSECURE — secret in compile-time config (embedded in release binary)
# config/config.exs
config :my_app, MyApp.Guardian,
  secret_key: "hardcoded_secret"

# ✅ SECURE — secret from environment at runtime
# config/runtime.exs
config :my_app, MyApp.Guardian,
  secret_key: System.fetch_env!("GUARDIAN_SECRET_KEY"),
  ttl: {15, :minutes},
  allowed_algos: ["HS512"]

# ✅ SECURE — session fixation prevention in Phoenix controller
def create(conn, %{"email" => email, "password" => password}) do
  case Pow.Plug.authenticate_user(conn, %{"email" => email, "password" => password}) do
    {:ok, conn} ->
      conn
      |> configure_session(renew: true)   # prevents session fixation
      |> redirect(to: "/dashboard")
    {:error, conn} ->
      conn |> put_status(401) |> render("error.json")
  end
end

# ✅ SECURE — endpoint.ex session cookie
plug Plug.Session,
  store: :cookie,
  key: "_my_app_key",
  signing_salt: System.fetch_env!("SESSION_SALT"),
  secure: true,
  http_only: true,
  same_site: "Lax",
  max_age: 86_400
```

---

## 10. Phoenix-Specific Security

**Vulnerability:** Phoenix LiveView, CORS misconfiguration, disabled CSRF protection, missing security headers, and `render` with user-controlled template paths are common Phoenix-specific vulnerabilities.

**References:** CWE-352, CWE-79, CVE-2023-36126 (Phoenix LiveView XSS), OWASP CSRF

### Mandatory Rules

- **Never disable `Plug.CSRFProtection`** for non-API endpoints — it is enabled by default in Phoenix and must not be removed from the pipeline.
- **Configure CORS explicitly** via `cors_plug` — never use `allow_origin: "*"` for endpoints that accept credentials; specify exact origins.
- **Never use `raw/1` or `Phoenix.HTML.raw/1` with user-supplied content** in HEEx templates — auto-escaping is the default; `raw` bypasses it.
- **LiveView `handle_event/3` must authorize every action** — events come from untrusted clients; validate permissions on every event handler.
- **Never use `assigns` from `socket.assigns` as trusted without validation** — LiveView assigns can be manipulated between client and server via forged pushes in older versions.
- **Set security headers** via `Plug.Conn.put_resp_header` or a dedicated plug for: `Content-Security-Policy`, `X-Frame-Options`, `X-Content-Type-Options`, `Strict-Transport-Security`.
- **Avoid `Phoenix.Controller.render/3` with a user-controlled template name** — only render templates defined at compile time.

```elixir
# ❌ INSECURE — XSS: raw/1 bypasses HEEx auto-escaping
<%= raw @user_bio %>

# ❌ INSECURE — CORS allows all origins with credentials
plug CORSPlug, origin: "*"

# ❌ INSECURE — LiveView event without authorization
def handle_event("delete_post", %{"id" => id}, socket) do
  Posts.delete(id)  # no check that current_user owns post!
  {:noreply, socket}
end

# ✅ SECURE — HEEx auto-escaping (default)
<%= @user_bio %>

# ✅ SECURE — CORS with explicit allowed origins
plug CORSPlug, origin: ["https://app.example.com", "https://admin.example.com"]

# ✅ SECURE — LiveView event with authorization
def handle_event("delete_post", %{"id" => id}, socket) do
  post = Posts.get_post!(id)
  if post.user_id == socket.assigns.current_user.id do
    Posts.delete(post)
    {:noreply, update(socket, :posts, &Enum.reject(&1, fn p -> p.id == post.id end))}
  else
    {:noreply, put_flash(socket, :error, "Not authorized")}
  end
end

# ✅ SECURE — security headers plug
defmodule MyAppWeb.SecurityHeaders do
  import Plug.Conn
  def init(opts), do: opts
  def call(conn, _opts) do
    conn
    |> put_resp_header("x-frame-options", "DENY")
    |> put_resp_header("x-content-type-options", "nosniff")
    |> put_resp_header("x-xss-protection", "1; mode=block")
    |> put_resp_header("strict-transport-security", "max-age=31536000; includeSubDomains")
    |> put_resp_header("content-security-policy", "default-src 'self'")
  end
end
```

---

## 11. Secrets Management

**Vulnerability:** Elixir configuration has two phases: compile-time (`config/config.exs`, `config/dev.exs`, `config/prod.exs`) and runtime (`config/runtime.exs`). Secrets placed in compile-time config are embedded into release artifacts and can be extracted from the compiled BEAM files or release tarballs.

**References:** CWE-321, CWE-798, OWASP Sensitive Data Exposure

### Mandatory Rules

- **Place all secrets in `config/runtime.exs`** using `System.fetch_env!/1` — never in `config/prod.exs` or `config/config.exs`.
- **Never hardcode secrets in source files** — database passwords, API keys, JWT secrets, signing salts must come from environment variables or a secrets manager.
- **Use `System.fetch_env!/1` not `System.get_env/1`** for required secrets — `fetch_env!` crashes fast on missing values at startup rather than failing silently later.
- **Add `.env`, `*.secret.exs`, `secret.exs` to `.gitignore`** — never commit local secret configuration.
- **Use Vault or a cloud secrets manager** for production — reference via environment variables injected at runtime (Kubernetes Secrets, AWS Secrets Manager, etc.).
- **Rotate `secret_key_base`** (invalidates all sessions/tokens) on suspected compromise — store in environment, not code.

```elixir
# ❌ INSECURE — secret in compile-time config: embedded in release
# config/prod.exs
config :my_app, MyAppWeb.Endpoint,
  secret_key_base: "abc123hardcoded..."

# ❌ INSECURE — System.get_env returns nil silently if missing
config :my_app, :database_url, System.get_env("DATABASE_URL")

# ✅ SECURE — runtime config with required env vars
# config/runtime.exs
import Config

config :my_app, MyAppWeb.Endpoint,
  secret_key_base: System.fetch_env!("SECRET_KEY_BASE")

config :my_app, MyApp.Repo,
  url: System.fetch_env!("DATABASE_URL"),
  pool_size: String.to_integer(System.get_env("POOL_SIZE") || "10")

config :my_app, MyApp.Guardian,
  secret_key: System.fetch_env!("GUARDIAN_SECRET_KEY")
```

---

## 12. Process and Message Security

**Vulnerability:** Elixir processes communicate via messages — sending crafted messages to named processes or using `send/2` with a user-controlled PID can trigger unintended state changes. Registered process names derived from user input create atom exhaustion and allow message spoofing.

**References:** CWE-400, CWE-284, Erlang process security

### Mandatory Rules

- **Never derive registered process names from user input** — use static atoms or a controlled Registry with server-managed keys.
- **Validate messages in `handle_info/2` and `handle_cast/2`** — pattern match strictly; unmatched messages should be logged and dropped, not crash the process.
- **Use `GenServer.call/3` timeouts** — always specify a timeout to prevent indefinite blocking: `GenServer.call(pid, msg, 5_000)`.
- **Never expose raw PIDs to clients** — PID serialization (`inspect/1`) creates strings that clients can send back; validate on receipt.
- **Use `Task.Supervisor.async_nolink/3`** for tasks spawned from web requests — prevents crashes in background tasks from killing the request process.
- **Set `max_heap_size` for processes handling untrusted data** to prevent memory exhaustion via large message payloads.

```elixir
# ❌ INSECURE — process name from user input: atom exhaustion + spoofing
name = String.to_atom("worker_" <> params["tenant"])
GenServer.call(name, :get_status)

# ❌ INSECURE — handle_info with catch-all: accepts any message
def handle_info(_msg, state), do: {:noreply, state}

# ✅ SECURE — Registry with server-controlled keys
def start_worker(tenant_id) when is_integer(tenant_id) do
  name = {:via, Registry, {MyApp.Registry, tenant_id}}
  DynamicSupervisor.start_child(MyApp.DynamicSupervisor, {MyApp.Worker, name: name})
end

# ✅ SECURE — strict pattern matching in handle_info
def handle_info({:event, %MyApp.Event{} = event}, state) do
  process_event(event, state)
end
def handle_info(unexpected, state) do
  Logger.warning("Unexpected message: #{inspect(unexpected)}")
  {:noreply, state}
end

# ✅ SECURE — bounded process memory for untrusted data
Process.flag(:max_heap_size, %{size: 100_000, kill: true, error_logger: true})
```

---

## 13. Logging and Sensitive Data Exposure

**Vulnerability:** Elixir's `Logger` and Phoenix request logging can inadvertently capture passwords, tokens, credit card numbers, and PII. Phoenix's debug error pages expose stack traces and environment variables in development — misconfigurations can leak them in production.

**References:** CWE-532, CWE-209, OWASP Sensitive Data Exposure

### Mandatory Rules

- **Filter sensitive parameters from Phoenix request logs** in `endpoint.ex`: `filter_parameters: ["password", "token", "secret", "api_key", "credit_card"]`.
- **Set `config :phoenix, :filter_parameters`** to extend the default filter list beyond `["password"]`.
- **Never log structs containing sensitive fields with `inspect/1`** — implement `Inspect` protocol with redaction for sensitive structs.
- **Set `config :my_app, MyAppWeb.Endpoint, debug_errors: false`** in production — `config/runtime.exs`.
- **Avoid `Logger.debug(inspect(params))`** in request handlers — log only safe, pre-filtered fields.
- **Use `Logger.metadata/1`** to attach request IDs rather than embedding full request data in log messages.

```elixir
# ✅ SECURE — endpoint.ex: filter sensitive params from request logs
config :my_app, MyAppWeb.Endpoint,
  http: [ip: {127, 0, 0, 1}, port: 4000],
  render_errors: [formats: [html: MyAppWeb.ErrorHTML, json: MyAppWeb.ErrorJSON], layout: false],
  pubsub_server: MyApp.PubSub,
  live_view: [signing_salt: System.fetch_env!("LIVE_VIEW_SALT")]

config :phoenix, :filter_parameters, [
  "password", "password_confirmation",
  "token", "secret", "api_key", "auth_token",
  "credit_card", "cvv", "ssn"
]

# ✅ SECURE — redact sensitive fields in Inspect protocol
defimpl Inspect, for: MyApp.User do
  def inspect(%{id: id, email: email}, _opts) do
    "#MyApp.User<id: #{id}, email: #{email}>"
  end
end

# ✅ SECURE — structured logging without sensitive data
Logger.info("User login attempt", user_id: user.id, ip: remote_ip)
```

---

## 14. TLS and Erlang/OTP Network Security

**Vulnerability:** Erlang/OTP has had critical vulnerabilities in its TLS and SSH implementations. CVE-2025-32433 (March 2025) is a critical unauthenticated RCE in the Erlang/OTP SSH daemon — any Elixir application using `ssh` or `:ssh` directly on an unpatched OTP version is vulnerable.

**References:** CVE-2025-32433 (OTP SSH RCE), CVE-2022-37026 (OTP TLS), CVE-2024-27416 (OTP SSH)

### Mandatory Rules

- **Keep Erlang/OTP updated** — subscribe to Erlang security advisories; patch within 7 days for Critical CVEs.
- **Never expose the Erlang SSH daemon (`:ssh.daemon/2`)** on public interfaces without authentication and IP allowlisting.
- **Disable the Erlang distribution port** (4369/epmd + cookie auth) in production containers — set `--erl "-proto_dist inet_tls"` or disable clustering if not needed.
- **Use TLS 1.2+ for all `:ssl` connections** — set `versions: [:"tlsv1.2", :"tlsv1.3"]` in SSL options; do not allow `:"tlsv1"` or `:"tlsv1.1"`.
- **Verify peer certificates** — set `verify: :verify_peer`, `cacertfile: CAStore.file_path()`, `depth: 3`; never `verify: :verify_none` in production.
- **Configure `secure_renegotiate: true`** in SSL options to prevent renegotiation attacks.

```elixir
# ❌ INSECURE — TLS with no peer verification
:ssl.connect(host, 443, verify: :verify_none)

# ❌ INSECURE — allows obsolete TLS versions
:ssl.connect(host, 443, versions: [:"tlsv1", :"tlsv1.1", :"tlsv1.2"])

# ✅ SECURE — TLS with certificate verification
:ssl.connect(host, 443,
  verify: :verify_peer,
  cacertfile: CAStore.file_path(),
  versions: [:"tlsv1.2", :"tlsv1.3"],
  secure_renegotiate: true,
  depth: 3
)

# ✅ SECURE — Mint/Req HTTP client with verified TLS (recommended over raw :ssl)
Req.get!("https://api.example.com/data",
  connect_options: [transport_opts: [cacerts: :public_key.cacerts_get()]]
)
```

---

## 15. Authorization (Bodyguard / Policy Modules)

**Vulnerability:** Missing authorization checks — especially in LiveView event handlers and background tasks — are the top finding in Elixir/Phoenix applications. Controllers that query resources without scoping to the current user expose all records (IDOR).

**References:** CWE-285, CWE-639, OWASP Broken Access Control

### Mandatory Rules

- **Always scope database queries to the current user** — `current_user |> Ecto.assoc(:posts) |> Repo.get!(id)` rather than `Repo.get!(Post, id)`.
- **Use a centralized policy library** (Bodyguard, Canada) — scattered `if current_user.role == :admin` checks are error-prone.
- **Authorize in `Plug`/`Phoenix.Controller.action_fallback`** — every controller action must have an explicit authorization check.
- **LiveView: re-authorize on every event** — `socket.assigns.current_user` is set at mount time; verify ownership on every `handle_event`.
- **Context functions must accept and enforce `current_user`** — `Posts.delete_post(current_user, post_id)` not `Posts.delete_post(post_id)`.

```elixir
# ❌ INSECURE — loads any post by ID (IDOR)
def show(conn, %{"id" => id}) do
  post = Repo.get!(Post, id)
  render(conn, "show.html", post: post)
end

# ✅ SECURE — scoped to current user via association
def show(conn, %{"id" => id}) do
  post = conn.assigns.current_user
         |> Ecto.assoc(:posts)
         |> Repo.get!(id)
  render(conn, "show.html", post: post)
end

# ✅ SECURE — Bodyguard policy check
def show(conn, %{"id" => id}) do
  post = Repo.get!(Post, id)
  with :ok <- Bodyguard.permit(MyApp.Posts.Policy, :show, conn.assigns.current_user, post) do
    render(conn, "show.html", post: post)
  end
end
```

---

## 16. Supply Chain (mix_audit and Sobelow)

**Vulnerability:** Elixir projects depend on Hex packages which may have known CVEs. Sobelow is a Phoenix-specific static analysis tool that detects many of the vulnerabilities in this document automatically.

**References:** OWASP Supply Chain, CWE-1104

### Mandatory Rules

- **Run `mix deps.audit`** (mix_audit) in CI — checks all dependencies against the Hex vulnerability database.
- **Run `mix sobelow --config`** in CI for Phoenix projects — detects SQL injection, XSS, CSRF bypass, atom exhaustion, and more.
- **Commit and review `mix.lock`** in pull requests — lock file pinning prevents transitive dependency drift.
- **Keep OTP, Elixir, and all Hex dependencies current** — subscribe to Hex advisory feed and Erlang security mailing list.
- **Audit new dependencies** before adding — `mix hex.info <package>` shows downloads, last update, and retirement status.
- **Use `mix hex.audit`** to check for retired packages — retired packages may have unaddressed vulnerabilities.

```bash
# Install and run mix_audit
mix archive.install hex mix_audit
mix deps.audit

# Install and run sobelow
mix sobelow --config
# Generate config file: mix sobelow --save-config

# Check for retired packages
mix hex.audit

# Check for outdated dependencies
mix hex.outdated
```

---

## CVE Reference Table

| CVE | Severity | Component | Description | Fixed In |
|-----|----------|-----------|-------------|----------|
| CVE-2025-32433 | Critical (10.0) | Erlang/OTP SSH | Unauthenticated RCE in SSH daemon via pre-auth message handling | OTP 27.3.3 / 26.2.5.11 / 25.3.2.21 |
| CVE-2024-27416 | High (8.1) | Erlang/OTP SSH | SSH server mishandles connection messages, enabling RCE | OTP 26.2.3 |
| CVE-2022-37026 | Critical (9.8) | Erlang/OTP TLS | TLS server does not enforce client certificate authentication in `partial_chain` | OTP 25.1 / 24.3.4.4 / 23.3.4.17 |
| CVE-2020-35733 | High (7.5) | Erlang/OTP SSH | Buffer overflow in SSH daemon's `ssh_transport` | OTP 23.2 |
| CVE-2023-36126 | Medium (6.1) | Phoenix LiveView | XSS via unsanitized `phx-click` attribute values in older LiveView | LiveView 0.19.3 |
| CVE-2019-15160 | Medium (5.3) | Plug | `Plug.Static` path traversal on Windows via backslash | Plug 1.8.3 |
| CVE-2021-29391 | Medium (5.9) | Quantum (Elixir) | Timing side-channel in scheduler token comparison | quantum-core 3.3.0 |
| CVE-2023-52045 | High (7.5) | Erlang/OTP | SSL application crash via crafted TLS handshake | OTP 26.1 / 25.3.2.9 |

---

## Security Checklist

### Code Injection
- [ ] `Code.eval_string/2`, `Code.eval_file/2`, `Code.compile_string/2` not called with user data
- [ ] `EEx.eval_string/2` not called with user-supplied template strings
- [ ] `:erlang.apply/3` with dynamic module/function uses an explicit allowlist

### Atom Exhaustion
- [ ] `String.to_atom/1` not called with user-supplied strings anywhere in the codebase
- [ ] `String.to_existing_atom/1` used (with rescue) where atom conversion is necessary
- [ ] No `Enum.into(params, %{}, fn {k, v} -> {String.to_atom(k), v} end)` patterns

### Deserialization
- [ ] `:erlang.binary_to_term/1` only called with `[:safe]` flag or on trusted internal data
- [ ] ETF not used for client-facing or inter-service data exchange (JSON/Protobuf preferred)
- [ ] Erlang distribution port not exposed to public network

### SQL Injection (Ecto)
- [ ] No string interpolation in `Ecto.Query.fragment/1`
- [ ] No `Repo.query/2` calls with interpolated strings
- [ ] Dynamic `ORDER BY`/`GROUP BY` columns validated against an atom allowlist

### Command Injection
- [ ] `:os.cmd/1` not used with any user-supplied data
- [ ] `System.cmd/3` uses list form (not shell string)
- [ ] `Port.open` not used with user-controlled spawn strings

### Path Traversal
- [ ] All file paths canonicalized with `Path.expand/1` and verified against base directory
- [ ] `Path.safe_relative/2` used where available (Elixir 1.14+)
- [ ] Uploaded files stored with UUID names, not original filenames

### XML
- [ ] `SweetXml.parse/2` not called on untrusted XML — `Saxy` used instead
- [ ] `xmerl` entity resolution disabled for untrusted XML

### Cryptography
- [ ] `Bcrypt.hash_pwd_salt/2` or `Argon2.hash_pwd_salt/2` used for password hashing
- [ ] No MD5 or SHA-1 for password hashing or security-sensitive digests
- [ ] AES-256-GCM used for symmetric encryption with authentication tag verified
- [ ] Unique IV generated per encryption with `:crypto.strong_rand_bytes(12)`
- [ ] Tokens generated with `:crypto.strong_rand_bytes/1` — not `:rand.uniform/1`
- [ ] Constant-time comparison used for HMAC/token verification

### Authentication and Session
- [ ] Guardian `secret_key` in `config/runtime.exs` (not `config/prod.exs`)
- [ ] All JWT tokens have `ttl` set; `"none"` algorithm rejected
- [ ] `configure_session(conn, renew: true)` called on login (session fixation prevention)
- [ ] Session cookie has `secure: true`, `http_only: true`, `same_site: "Lax"`

### Phoenix Security
- [ ] `Plug.CSRFProtection` not disabled for browser endpoints
- [ ] CORS not configured with wildcard `"*"` for credentialed requests
- [ ] `raw/1` / `Phoenix.HTML.raw/1` not used with user-supplied strings in HEEx
- [ ] Every LiveView `handle_event/3` has authorization check for current user
- [ ] Security headers set: CSP, X-Frame-Options, X-Content-Type-Options, HSTS

### Secrets
- [ ] All secrets in `config/runtime.exs` using `System.fetch_env!/1`
- [ ] No secrets in `config/config.exs`, `config/prod.exs`, or source files
- [ ] `.env`, `secret.exs` in `.gitignore`

### Logging
- [ ] `config :phoenix, :filter_parameters` includes all sensitive parameter names
- [ ] `Inspect` protocol redacts sensitive fields on sensitive structs
- [ ] `config :my_app, MyAppWeb.Endpoint, debug_errors: false` in production runtime config

### TLS / OTP
- [ ] Erlang/OTP updated to latest patched version; subscribed to Erlang security advisories
- [ ] TLS connections use `verify: :verify_peer` with CA bundle
- [ ] TLS versions restricted to 1.2 and 1.3
- [ ] Erlang distribution port not exposed publicly; cookie set to a strong random value

### Supply Chain
- [ ] `mix deps.audit` runs in CI pipeline
- [ ] `mix sobelow --config` runs in CI pipeline for Phoenix projects
- [ ] `mix.lock` committed and reviewed in pull requests
- [ ] `mix hex.audit` checks for retired packages

---

## Tooling

| Tool | Purpose | Command |
|------|---------|---------|
| [Sobelow](https://github.com/nccgroup/sobelow) | Phoenix security static analyzer (SQL injection, XSS, CSRF, atom exhaustion, etc.) | `mix sobelow --config` |
| [mix_audit](https://github.com/mirego/mix_audit) | Checks Hex dependencies for known CVEs | `mix deps.audit` |
| [Credo](https://github.com/rrrene/credo) | Code quality + security-relevant style checks | `mix credo --strict` |
| [Dialyxir](https://github.com/jeremyjh/dialyxir) | Type analysis via Dialyzer — catches unsafe patterns | `mix dialyzer` |
| [mix hex.audit](https://hexdocs.pm/mix/Mix.Tasks.Hex.Audit.html) | Checks for retired Hex packages | `mix hex.audit` |
| [Erlang Security Advisories](https://erlang.org/news/tag/security/) | Official OTP CVE announcements | Monitor RSS feed |
| [OWASP ZAP](https://www.zaproxy.org/) | DAST for Phoenix web applications | `zap-baseline.py -t https://app.example.com` |
