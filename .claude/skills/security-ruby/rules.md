# 💎 Ruby Security Rules

> **Standard:** Security rules for Ruby 3.x and Ruby on Rails 7.x, covering language-level risks, Rails-specific attack vectors, and ecosystem supply chain.
> **Sources:** Ruby Security Advisories, Rails Security Guide, OWASP Ruby on Rails Cheat Sheet, NIST NVD, Snyk Ruby Vulnerability DB, HackerOne Rails disclosures
> **Version:** 1.0.0
> **Last updated:** March 2026
> **Scope:** Ruby 3.x language runtime, Ruby on Rails 7.x, Sinatra, common gems (Devise, Nokogiri, CarrierWave, ActiveStorage, Pundit). Does not cover JRuby-specific JVM risks.

---

## General Instructions

Apply these rules when writing or reviewing Ruby and Rails code. Ruby's dynamic nature — `eval`, `send`, `method_missing`, open classes, and symbol coercion — creates a wide attack surface that differs significantly from statically typed languages. Rails' "magic" helpers (`html_safe`, `render`, `redirect_to`, `params`) are frequent sources of vulnerabilities when used carelessly. Pay special attention to the string-boundary anchoring difference (`^`/`$` vs `\A`/`\z`) and to deserialization via `Marshal` and `YAML`, both of which enable unauthenticated RCE.

---

## 1. Code Injection (eval and Dynamic Dispatch)

**Vulnerability:** Ruby's `eval`, `instance_eval`, `class_eval`, `binding.eval`, and `ERB.new(...).result` execute arbitrary Ruby code. Dynamic dispatch via `send`, `public_send`, and `method` with user-controlled method names allows calling any method on any object.

**References:** CWE-94, CWE-95, CVE-2019-5418, OWASP Code Injection

### Mandatory Rules

- **Never pass user-controlled data to `eval`, `instance_eval`, `class_eval`, `module_eval`, or `binding.eval`** — all evaluate arbitrary Ruby and enable RCE.
- **Never use `ERB.new(user_input).result` or `.result(binding)`** — renders arbitrary Ruby in the template string; use static template files only.
- **Never pass user input to `send` or `public_send` without an explicit allowlist** — allows calling any method including `eval`, `system`, `exit`.
- **Use `public_send` over `send`** — at minimum prevents calling private methods, but still requires an allowlist.
- **Avoid `Kernel.const_get(user_input)` without validation** — enables class lookup that can expose dangerous constants.

```ruby
# ❌ INSECURE — eval with user input: RCE
eval(params[:expression])

# ❌ INSECURE — ERB template from user input: RCE
ERB.new(params[:template]).result(binding)

# ❌ INSECURE — send with user-controlled method name
user.send(params[:action])

# ✅ SECURE — explicit allowlist for dynamic dispatch
ALLOWED_ACTIONS = %w[activate deactivate suspend].freeze
action = params[:action]
raise ArgumentError, "Invalid action" unless ALLOWED_ACTIONS.include?(action)
user.public_send(action)
```

---

## 2. SQL Injection (ActiveRecord)

**Vulnerability:** ActiveRecord allows raw string interpolation in query conditions, which bypasses parameterization. Methods like `where`, `order`, `group`, `having`, `select`, `from`, `joins`, and `find_by_sql` all accept raw SQL fragments when called with a string argument.

**References:** CWE-89, CVE-2022-32224, OWASP SQL Injection, Rails Security Guide §SQL Injection

### Mandatory Rules

- **Never interpolate user input directly into ActiveRecord query strings** — use the `?` placeholder or named bind parameters.
- **Never pass user input to `order`, `group`, `having`, `select`, or `from` without sanitization** — these methods do not auto-parameterize.
- **Use `ActiveRecord::Base.sanitize_sql_for_order` for dynamic order columns** — validates column names before interpolation.
- **Validate sort direction against an allowlist** — `["asc", "desc"].include?(dir) ? dir : "asc"`.
- **Never use `find_by_sql` or `connection.execute` with string interpolation** — use bind parameters.

```ruby
# ❌ INSECURE — string interpolation in where clause
User.where("email = '#{params[:email]}'")

# ❌ INSECURE — user-controlled order clause: SQL injection
User.order("#{params[:sort]} #{params[:dir]}")

# ❌ INSECURE — raw SQL with interpolation
User.find_by_sql("SELECT * FROM users WHERE name = '#{params[:name]}'")

# ✅ SECURE — parameterized where
User.where("email = ?", params[:email])
User.where(email: params[:email])

# ✅ SECURE — validated order clause
ALLOWED_COLUMNS = %w[name created_at email].freeze
ALLOWED_DIRS    = %w[asc desc].freeze
col = ALLOWED_COLUMNS.include?(params[:sort]) ? params[:sort] : "created_at"
dir = ALLOWED_DIRS.include?(params[:dir])     ? params[:dir]  : "asc"
User.order(Arel.sql("#{col} #{dir}"))

# ✅ SECURE — find_by_sql with bind parameters
User.find_by_sql(["SELECT * FROM users WHERE name = ?", params[:name]])
```

---

## 3. Command Injection

**Vulnerability:** Ruby provides multiple ways to execute shell commands: backticks, `%x{}`, `system()`, `exec()`, `spawn()`, `IO.popen()`, `Open3.*`. Passing user input via a single string argument triggers shell interpretation with full metacharacter expansion.

**References:** CWE-78, OWASP Command Injection

### Mandatory Rules

- **Never pass user input as part of a shell string to system commands** — use array form which bypasses the shell entirely.
- **Prefer array form for `system`, `exec`, `spawn`, `IO.popen`, `Open3.popen3`** — prevents shell interpretation.
- **Never use backticks (`` ` ``) or `%x{}` with user-supplied values** — no safe parameterized form exists.
- **Validate and allowlist any values used in command arguments** — even in array form, argument injection can occur for some tools.

```ruby
# ❌ INSECURE — shell string with user input: command injection
system("convert #{params[:filename]} output.png")
`ffmpeg -i #{user_file} out.mp4`

# ✅ SECURE — array form bypasses shell
system("convert", params[:filename], "output.png")
IO.popen(["ffmpeg", "-i", user_file, "out.mp4"])
Open3.capture2("convert", params[:filename], "output.png")

# ✅ SECURE — validate input before use
filename = params[:filename]
raise ArgumentError unless filename.match?(/\A[\w\-]+\.(jpg|png|gif)\z/)
system("convert", filename, "output.png")
```

---

## 4. Deserialization (Marshal and YAML)

**Vulnerability:** `Marshal.load` deserializes arbitrary Ruby objects and executes code during object instantiation. `YAML.load` (Psych) with untrusted input allows gadget chains that execute system commands. Both are exploitable without any special classes being loaded.

**References:** CWE-502, CVE-2013-0156 (Rails YAML RCE), CVE-2020-8165 (Rails Marshal cache RCE), CVE-2022-32224 (ActiveRecord YAML column)

### Mandatory Rules

- **Never call `Marshal.load` or `Marshal.restore` on untrusted data** — enables unauthenticated RCE via gadget chains.
- **Never call `YAML.load` on untrusted data** — use `YAML.safe_load` (allowlist-based) or `YAML.safe_load_file` instead.
- **Never use `Marshal` for inter-service communication or data storage accessible to untrusted parties** — prefer JSON or MessagePack.
- **Verify Rails cache store does not persist user-supplied data via Marshal** — `ActiveSupport::Cache::RedisCacheStore` marshals by default; do not cache user-supplied objects directly.
- **Pin Psych gem version** — Psych 4.0+ changed `YAML.load` to safe mode by default; do not downgrade.

```ruby
# ❌ INSECURE — Marshal.load on untrusted data: RCE
obj = Marshal.load(Base64.decode64(params[:data]))

# ❌ INSECURE — YAML.load on untrusted YAML: gadget chain RCE
config = YAML.load(File.read(params[:config_file]))

# ✅ SECURE — YAML.safe_load restricts to primitive types
config = YAML.safe_load(File.read("config/app.yml"),
                         permitted_classes: [Symbol])

# ✅ SECURE — use JSON for serialized data from external sources
obj = JSON.parse(Base64.decode64(params[:data]))
```

---

## 5. Path Traversal and File Operations

**Vulnerability:** Constructing file paths from user input enables directory traversal (`../../../etc/passwd`). Rails' `send_file` and `send_data` can serve arbitrary files if the path is not constrained. `File.read`, `File.open`, `IO.read`, and `Pathname` operations are equally affected.

**References:** CWE-22, CVE-2019-5418 (Rails `render file:` path traversal)

### Mandatory Rules

- **Canonicalize paths with `File.expand_path` or `Pathname#realpath` and verify the result starts with the expected base directory** — prevents traversal via `../`.
- **Never use `render file: params[:path]`** — exposes arbitrary file contents as a template (CVE-2019-5418); use static paths only.
- **Never construct file paths by concatenating user input** — use `File.join` with a validated, fixed base directory and a sanitized filename.
- **Strip directory components from user-supplied filenames** — use `File.basename(params[:filename])` before joining with the base path.
- **Use UUIDs or server-generated keys** as filenames for uploaded files — never use original filenames.

```ruby
# ❌ INSECURE — path traversal: reads /etc/passwd with ../../../../etc/passwd
content = File.read(Rails.root.join("uploads", params[:file]))

# ❌ INSECURE — CVE-2019-5418: renders arbitrary file
render file: params[:template]

# ✅ SECURE — canonicalize and verify prefix
BASE_DIR = Rails.root.join("uploads").freeze

def safe_path(user_filename)
  name     = File.basename(user_filename)           # strip directory components
  expanded = File.expand_path(File.join(BASE_DIR, name))
  raise ArgumentError, "Path traversal detected" unless expanded.start_with?(BASE_DIR.to_s)
  expanded
end

content = File.read(safe_path(params[:file]))
```

---

## 6. Mass Assignment (Strong Parameters)

**Vulnerability:** Rails strong parameters prevent mass assignment attacks, but incorrect use of `permit!`, overly broad `permit`, or merging of raw `params` into model attributes bypasses the protection. Attackers can set `admin: true`, `role: "superuser"`, or `balance: 999999`.

**References:** CWE-915, CVE-2012-2661 (historic Rails mass assignment), Rails Security Guide §Mass Assignment

### Mandatory Rules

- **Never use `params.permit!`** — permits all attributes including privileged ones; defeats strong parameters.
- **Never pass `params` directly to `.new`, `.create`, `.update`, or `.attributes=`** — always call `.require(:model).permit(:field1, :field2)` first.
- **Never permit sensitive attributes such as `role`, `admin`, `balance`, `confirmed`, `locked`** in user-facing forms — set these in the controller explicitly based on business logic.
- **Use nested `permit` for nested attributes** — `permit(address_attributes: [:street, :city])`.
- **Audit every `params.permit` call** in code review — it is a common omission.

```ruby
# ❌ INSECURE — permits all params including :admin, :role
@user = User.new(params[:user].permit!)

# ❌ INSECURE — raw params hash to model
@user = User.new(params[:user])

# ✅ SECURE — explicit allowlist
def user_params
  params.require(:user).permit(:name, :email, :password, :password_confirmation)
end

@user = User.new(user_params)

# ✅ SECURE — setting privileged attribute explicitly, not via permit
@user.role = "admin" if current_user.superadmin?
```

---

## 7. Cross-Site Scripting (ERB and html_safe)

**Vulnerability:** Rails auto-escapes ERB output in `<%= %>` blocks, but `html_safe`, `raw`, `<%== %>`, `content_tag` with user input, and `link_to` with user-controlled href bypass escaping and enable reflected or stored XSS.

**References:** CWE-79, CVE-2023-28362 (Rails XSS in Action View), OWASP XSS

### Mandatory Rules

- **Never call `.html_safe` or `raw()` on user-supplied strings** — marks the string as trusted without sanitizing it.
- **Use `sanitize()` with an explicit allowlist for rich user HTML** — the default Rails `sanitize` allowlist is permissive; restrict to `tags:` and `attributes:` you need.
- **Never build HTML strings with string interpolation and mark them safe** — use `content_tag` or ERB templates with auto-escaping.
- **Avoid `link_to user_input, href`** where `href` is user-controlled — always validate or sanitize URLs; reject `javascript:` schemes.
- **Use `json_escape` (alias: `j`) or `to_json` with `html_safe` only in script blocks** — prevents JSON→XSS in inline `<script>` tags.
- **Set Content Security Policy** via `ActionDispatch::ContentSecurityPolicy` as a defense-in-depth layer.

```ruby
# ❌ INSECURE — XSS: user content marked as safe
<%= user.bio.html_safe %>
<%= raw params[:message] %>

# ❌ INSECURE — XSS via link_to with javascript: scheme
<%= link_to "Click", params[:url] %>

# ✅ SECURE — auto-escaped (default behavior)
<%= user.bio %>

# ✅ SECURE — sanitize with allowlist for rich text
<%= sanitize user.bio, tags: %w[p b i a ul li], attributes: %w[href] %>

# ✅ SECURE — validate URL scheme before rendering
safe_url = URI.parse(params[:url]).then { |u|
  %w[http https].include?(u.scheme) ? u.to_s : "#"
}
<%= link_to "Visit", safe_url %>

# ✅ SECURE — JSON in script tags escaped for HTML context
<script>var data = <%= json_escape(data.to_json) %>;</script>
```

---

## 8. Regular Expression Pitfalls (ReDoS and Anchor Confusion)

**Vulnerability:** Ruby's `^` and `$` anchors match **line** boundaries, not string boundaries. A regex like `/^admin$/` matches the string `"innocent\nadmin"`, bypassing validation. Additionally, poorly written regexes with nested quantifiers cause catastrophic backtracking (ReDoS) under adversarial input.

**References:** CWE-1333, CVE-2023-22795 (Rails ReDoS in query parameter parsing), OWASP ReDoS

### Mandatory Rules

- **Always use `\A` (start of string) and `\z` (end of string) for input validation** — never `^` and `$` for security-sensitive checks.
- **Test regexes against multiline input with embedded newlines** — `"safe\nmalicious"` often bypasses `^`/`$` checks.
- **Avoid nested quantifiers on variable-width groups** — patterns like `/(a+)+$/` are vulnerable to ReDoS; rewrite with possessive quantifiers or atomic groups.
- **Set a regex timeout for user-supplied patterns** — wrap in `Timeout.timeout(0.5)` or avoid executing user-supplied patterns entirely.
- **Use `Regexp.new(Regexp.escape(user_input))` when incorporating user input into a pattern** — prevents pattern injection.

```ruby
# ❌ INSECURE — ^ and $ match line boundaries, not string
raise "Invalid role" unless role =~ /^admin$/
# "user\nadmin" passes this check!

# ✅ SECURE — \A and \z match full string
raise "Invalid role" unless role.match?(/\Aadmin\z/)

# ❌ INSECURE — catastrophic backtracking on long repeated input
"aaaaaaaaaaaaaaaaaaaab".match?(/^(a+)+$/)  # hangs

# ✅ SECURE — rewrite without nested quantifiers
"aaaaaaaaaaaaaaaaaaaab".match?(/\Aa+\z/)

# ✅ SECURE — escape user input before embedding in pattern
pattern = /\A#{Regexp.escape(params[:prefix])}/
```

---

## 9. Cryptography

**Vulnerability:** Ruby's `OpenSSL` and `Digest` modules are low-level and easy to misuse — wrong cipher modes, IV reuse, weak algorithms, and missing authentication tags are common. `Digest::MD5` and `Digest::SHA1` are still available but cryptographically broken.

**References:** CWE-327, CWE-328, CWE-330, OWASP Cryptographic Failures

### Mandatory Rules

- **Never use `Digest::MD5` or `Digest::SHA1` for password hashing or security-sensitive integrity checks** — use BCrypt (`bcrypt` gem) for passwords, SHA-256+ for non-password digests.
- **Use BCrypt for all password hashing** — `BCrypt::Password.create(password, cost: 12)`; never store plaintext or hex-digested passwords.
- **Use AES-256-GCM for symmetric encryption** — provides both confidentiality and authentication; do not use ECB or CBC without MAC.
- **Generate a unique random IV for every encryption operation** — `OpenSSL::Random.random_bytes(12)` for GCM; never hardcode or reuse IVs.
- **Verify the GCM authentication tag** on decryption — `cipher.auth_tag = tag` before `cipher.final`.
- **Use `ActiveSupport::SecurityUtils.secure_compare`** for constant-time string comparison of tokens and HMACs — prevents timing attacks.
- **Generate tokens with `SecureRandom.hex(32)` or `SecureRandom.urlsafe_base64(32)`** — never `rand` or `Time.now`.

```ruby
# ❌ INSECURE — MD5 for password: crackable
User.password_hash = Digest::MD5.hexdigest(password)

# ❌ INSECURE — AES-CBC without authentication
cipher = OpenSSL::Cipher.new("AES-256-CBC")

# ✅ SECURE — BCrypt for passwords
require "bcrypt"
hashed = BCrypt::Password.create(password, cost: 12)
BCrypt::Password.new(hashed) == password  # verification

# ✅ SECURE — AES-256-GCM with unique IV
cipher = OpenSSL::Cipher.new("aes-256-gcm")
cipher.encrypt
cipher.key = key          # 32 random bytes, stored securely
cipher.iv  = iv = OpenSSL::Random.random_bytes(12)
cipher.auth_data = ""
ciphertext = cipher.update(plaintext) + cipher.final
tag = cipher.auth_tag     # store alongside ciphertext and iv

# ✅ SECURE — constant-time comparison
ActiveSupport::SecurityUtils.secure_compare(token_from_request, expected_token)
```

---

## 10. XML External Entity Injection (XXE) — Nokogiri

**Vulnerability:** Nokogiri parses XML with libxml2, which by default resolves external entities. An attacker can read local files or trigger SSRF by injecting a DOCTYPE with an external entity reference.

**References:** CWE-611, OWASP XXE, Nokogiri Security Guide

### Mandatory Rules

- **Disable external entity resolution and DTD processing when parsing untrusted XML** — pass `Nokogiri::XML::ParseOptions::NONET | Nokogiri::XML::ParseOptions::NOENT`.
- **Use `Nokogiri::XML(input) { |c| c.nonet.noent }` for a safe parse** — disables network access and entity substitution.
- **Never parse user-supplied XML with default options** — libxml2 defaults allow external entities.
- **Prefer `strict` mode parsing** — raises on malformed input rather than silently recovering.

```ruby
# ❌ INSECURE — default parse: external entities resolved, SSRF/file read
doc = Nokogiri::XML(user_xml)

# ✅ SECURE — disable network + entity resolution
doc = Nokogiri::XML(user_xml) { |config| config.nonet.noent }

# ✅ SECURE — explicit parse options constant
options = Nokogiri::XML::ParseOptions::NONET |
          Nokogiri::XML::ParseOptions::NOENT  |
          Nokogiri::XML::ParseOptions::NOBLANKS
doc = Nokogiri::XML(user_xml, nil, nil, options)
```

---

## 11. Session Management and Authentication

**Vulnerability:** Weak session configuration, session fixation, insecure `secret_key_base` management, and predictable token generation are common Rails authentication issues. Devise misconfiguration can disable security controls silently.

**References:** CWE-384, CWE-613, CVE-2024-26144 (Rails session cookie exposure), Rails Security Guide §Sessions

### Mandatory Rules

- **Store `secret_key_base` in environment variables or a secrets manager** — never commit to version control; rotate on compromise.
- **Use `httponly: true` and `secure: true` for all session cookies** — set in `config/initializers/session_store.rb`.
- **Set `SameSite: Strict` or `Lax`** on session cookies — mitigates CSRF for non-API apps.
- **Regenerate the session after login** — call `reset_session` before setting `session[:user_id]` to prevent session fixation.
- **Set absolute and idle timeouts** — `Devise.timeout_in = 30.minutes`; add absolute expiry for sensitive apps.
- **Use `has_secure_password`** built into Rails for simple password hashing — wraps BCrypt correctly.
- **Never store sensitive data in Rails cookies directly** — cookie store is signed but client-readable; use server-side sessions for PII.

```ruby
# ❌ INSECURE — session fixation: reuses attacker-controlled session ID
session[:user_id] = user.id

# ✅ SECURE — regenerate session on authentication
reset_session
session[:user_id] = user.id

# ✅ SECURE — session cookie configuration
Rails.application.config.session_store :cookie_store,
  key: "_app_session",
  secure: Rails.env.production?,
  httponly: true,
  same_site: :lax,
  expire_after: 2.hours
```

---

## 12. Open Redirect

**Vulnerability:** `redirect_to params[:return_to]` allows attackers to redirect users to phishing sites after login. Rails allows arbitrary URLs in `redirect_to` unless explicitly constrained.

**References:** CWE-601, CVE-2021-44528 (Rails open redirect), CVE-2024-41128 (Rails Action Pack open redirect)

### Mandatory Rules

- **Never pass user-controlled parameters directly to `redirect_to`** — validate that the target URL is on the allowed domain.
- **Use `redirect_back(fallback_location: root_path)` instead of `redirect_to params[:return_to]`** — limits redirect to the referrer.
- **Validate redirect targets with `url_whitelist` or a domain check** before redirecting.
- **Strip or reject URLs with `//` prefix** — `//evil.com/path` is treated as scheme-relative and bypasses host checks.

```ruby
# ❌ INSECURE — open redirect
redirect_to params[:return_to]

# ❌ INSECURE — insufficient host check (bypassed by //evil.com)
uri = URI.parse(params[:return_to])
redirect_to(uri.host == request.host ? params[:return_to] : root_path)

# ✅ SECURE — safe_redirect validates the URL fully
def safe_redirect_url(url)
  uri = URI.parse(url)
  # Allow only relative URLs or same host/scheme
  return root_path unless uri.host.nil? || uri.host == request.host
  return root_path unless uri.scheme.nil? || %w[http https].include?(uri.scheme)
  url
rescue URI::InvalidURIError
  root_path
end

redirect_to safe_redirect_url(params[:return_to])
```

---

## 13. Rails-Specific Pitfalls

**Vulnerability:** Several Rails helpers and patterns that appear safe have dangerous edge cases: `render params[:template]` executes arbitrary templates (SSTI), `link_to` with user href enables `javascript:` XSS, default `protect_from_forgery` settings can be bypassed in API controllers.

**References:** CVE-2019-5418, CVE-2023-28362, Rails Security Guide

### Mandatory Rules

- **Never use `render params[:template]` or `render params[:action]`** — enables server-side template injection; use a static string or an allowlist.
- **Never disable `protect_from_forgery` without a replacement** — API controllers using tokens must validate the token explicitly.
- **Avoid `content_tag` with unescaped user data** in the content argument — use ERB auto-escaping in views instead.
- **Set `config.force_ssl = true`** in production — enforces HTTPS and sets HSTS header.
- **Enable `config.action_dispatch.default_headers`** — includes `X-Frame-Options`, `X-XSS-Protection`, `X-Content-Type-Options` by default; do not remove them.
- **Never use `update_all` with user-controlled attribute hashes** — bypasses validations and callbacks but does not bypass SQL injection if the hash contains interpolated SQL.

```ruby
# ❌ INSECURE — SSTI: renders arbitrary template file
render params[:template]

# ❌ INSECURE — SSTI: arbitrary action render
render action: params[:action]

# ✅ SECURE — static allowlist for dynamic render
ALLOWED_TEMPLATES = %w[welcome dashboard profile].freeze
tmpl = ALLOWED_TEMPLATES.include?(params[:template]) ? params[:template] : "welcome"
render tmpl

# ✅ SECURE — Content Security Policy
# config/initializers/content_security_policy.rb
Rails.application.config.content_security_policy do |policy|
  policy.default_src :self
  policy.script_src  :self
  policy.style_src   :self
  policy.img_src     :self, :data
  policy.connect_src :self
  policy.font_src    :self
end
```

---

## 14. File Upload Security

**Vulnerability:** Accepting file uploads without validating content type by magic bytes, without renaming files, or without storing files outside the web root enables code execution, path traversal, and content injection.

**References:** CWE-434, CWE-22, OWASP File Upload Cheat Sheet

### Mandatory Rules

- **Validate file type by magic bytes** (content inspection), not by extension or `Content-Type` header — both are user-controlled.
- **Rename uploaded files with UUIDs** — never use original filenames; they may contain path traversal characters or executable extensions.
- **Store uploads outside the web root** or in object storage (S3, GCS) — files in `public/` are served directly by the web server.
- **Serve uploaded files through a controller action** with `Content-Disposition: attachment` — prevents browser execution of HTML/JS uploads.
- **Limit file size** at the application and web server level — prevent DoS via oversized uploads.
- **When using CarrierWave**, set `content_type_allowlist` and `extension_allowlist`; enable `sanitize_regexp` for filenames.
- **When using ActiveStorage**, configure `content_types_to_serve_as_binary` to prevent serving user HTML as text/html.

```ruby
# ❌ INSECURE — trusts Content-Type header and uses original filename
def upload
  file = params[:file]
  FileUtils.cp(file.tempfile, Rails.root.join("public/uploads", file.original_filename))
end

# ✅ SECURE — validates magic bytes and uses UUID filename
ALLOWED_MAGIC = {
  "\xFF\xD8\xFF"     => "image/jpeg",
  "\x89PNG\r\n\x1A\n" => "image/png",
  "GIF87a"           => "image/gif",
  "GIF89a"           => "image/gif",
}.freeze

def upload
  file = params[:file]
  header = File.read(file.tempfile.path, 8)
  raise ArgumentError, "Invalid file type" unless ALLOWED_MAGIC.any? { |sig, _| header.start_with?(sig) }

  safe_name = "#{SecureRandom.uuid}#{File.extname(file.original_filename).downcase}"
  dest = Rails.root.join("storage/uploads", safe_name)
  FileUtils.cp(file.tempfile.path, dest)
end
```

---

## 15. Authorization and Privilege Escalation

**Vulnerability:** Missing authorization checks (IDOR, broken access control) are the top-ranked finding in Rails applications. Controllers that load resources using `params[:id]` without scoping to the current user expose every record in the database.

**References:** CWE-285, CWE-639, OWASP Broken Access Control

### Mandatory Rules

- **Always scope resource lookups to the current user** — `current_user.posts.find(params[:id])` not `Post.find(params[:id])`.
- **Use a centralized authorization library** (Pundit or CanCanCan) — scattered `if current_user.admin?` checks are error-prone.
- **Use `before_action` to authorize resources** — never rely on view-layer hiding alone.
- **Apply `policy_scope` to collection queries** — prevents listing records the user should not see.
- **Verify authorization on every action including `update` and `destroy`** — adding CRUD actions later without authorization is common.

```ruby
# ❌ INSECURE — loads any post by ID, regardless of ownership (IDOR)
def show
  @post = Post.find(params[:id])
end

# ✅ SECURE — scoped to current user
def show
  @post = current_user.posts.find(params[:id])
end

# ✅ SECURE — Pundit authorization
def show
  @post = Post.find(params[:id])
  authorize @post          # raises Pundit::NotAuthorizedError if denied
end

# ✅ SECURE — Pundit scope for index
def index
  @posts = policy_scope(Post)
end
```

---

## 16. Sensitive Data Exposure and Logging

**Vulnerability:** Rails logs request parameters by default. Unfiltered logs expose passwords, tokens, SSNs, credit card numbers, and API keys. Production error pages with `consider_all_requests_local = true` expose stack traces with environment variables.

**References:** CWE-532, CWE-209, Rails Security Guide §Logging

### Mandatory Rules

- **Set `config.consider_all_requests_local = false`** in `config/environments/production.rb` — prevents stack trace exposure.
- **Filter sensitive parameters from logs** in `config/application.rb`:
  `config.filter_parameters += [:password, :token, :secret, :key, :api_key, :credit_card, :ssn]`
- **Never log sensitive attributes** explicitly — `Rails.logger.info(user.inspect)` may include passwords if the model doesn't override `inspect`.
- **Override `inspect`** on models with sensitive fields: `def inspect; "#<User id=#{id}>"; end`.
- **Set `config.log_level = :warn`** in production — reduces verbosity and accidental data leakage.
- **Avoid logging full request bodies** — they may contain passwords or payment data.

```ruby
# ✅ SECURE — config/application.rb: filter sensitive params from logs
config.filter_parameters += [
  :password, :password_confirmation,
  :token, :secret, :api_key, :auth_token,
  :credit_card_number, :ssn, :cvv
]

# ✅ SECURE — override inspect on sensitive models
class User < ApplicationRecord
  def inspect
    "#<User id=#{id} email=#{email.inspect}>"
  end
end

# ✅ SECURE — production environment settings
# config/environments/production.rb
config.consider_all_requests_local = false
config.log_level = :warn
```

---

## CVE Reference Table

| CVE | Severity | Component | Description | Fixed In |
|-----|----------|-----------|-------------|----------|
| CVE-2013-0156 | Critical (10.0) | Rails (YAML) | XML/YAML parameter deserialization enables RCE | Rails 2.3.15 / 3.0.19 / 3.1.10 / 3.2.11 |
| CVE-2019-5418 | High (7.5) | Action View | `render file:` path traversal leaks arbitrary files | Rails 4.2.11.1 / 5.0.7.2 / 5.1.6.2 / 5.2.2.1 / 6.0.0.beta3 |
| CVE-2020-8165 | Critical (9.8) | ActiveSupport | Unsafe deserialization in `MemCacheStore` / `RedisCacheStore` | Rails 5.2.4.3 / 6.0.3.1 |
| CVE-2021-44528 | Medium (6.1) | Action Pack | Open redirect in `redirect_to` with `//` prefix bypass | Rails 6.0.4.2 / 6.1.4.2 / 7.0.0.rc2 |
| CVE-2022-32224 | Critical (9.8) | ActiveRecord | YAML deserialization in column type coercion enables RCE | Rails 5.2.8.1 / 6.0.5.1 / 6.1.6.1 / 7.0.2.4 |
| CVE-2022-23633 | High (7.5) | Action Pack | Response body leaked between requests under certain middleware | Rails 5.2.7.1 / 6.0.4.5 / 6.1.4.5 / 7.0.0.1 |
| CVE-2023-22795 | Medium (5.3) | Action Dispatch | ReDoS in `ActionDispatch::Request#host` parsing | Rails 6.0.6.1 / 6.1.7.1 / 7.0.4.1 |
| CVE-2023-28362 | Medium (6.1) | Action View | XSS via `link_to` with unsanitized href | Rails 6.0.6.1 / 6.1.7.3 / 7.0.5.1 |
| CVE-2024-26144 | Medium (5.3) | Action Pack | Session cookie key exposed via cache timing in some configurations | Rails 7.1.3.3 |
| CVE-2024-41128 | Medium (6.1) | Action Pack | Open redirect via scheme-relative URLs (`//evil.com`) | Rails 7.0.8.5 / 7.1.4.1 / 7.2.1.1 |

---

## Security Checklist

### Injection
- [ ] No `eval`, `instance_eval`, `class_eval`, or `ERB.new(user_input).result` called with untrusted data
- [ ] All `send` / `public_send` calls use an explicit allowlist of method names
- [ ] No string interpolation in ActiveRecord `where`, `order`, `group`, `having`, `select`, or `find_by_sql`
- [ ] All dynamic order/sort columns validated against an allowlist; direction validated against `["asc","desc"]`
- [ ] Shell commands use array form (`system("cmd", arg1, arg2)`) — no string-form with user input
- [ ] No backticks or `%x{}` with user-supplied values

### Deserialization
- [ ] `Marshal.load` / `Marshal.restore` never called on untrusted data
- [ ] `YAML.load` replaced with `YAML.safe_load` for untrusted input
- [ ] Rails cache does not store user-supplied Ruby objects (Marshal-serialized)

### File Operations
- [ ] All file paths canonicalized with `File.expand_path` and verified to start with the allowed base directory
- [ ] No `render file: params[:...]` or `render action: params[:...]` anywhere in controllers
- [ ] Uploaded files renamed with UUIDs; original filenames never used on disk
- [ ] File types validated by magic bytes, not extension or Content-Type header
- [ ] Uploads stored outside public web root

### Mass Assignment
- [ ] No `params.permit!` anywhere in the codebase
- [ ] No raw `params[:model]` passed to `.new`, `.create`, `.update`, or `.attributes=`
- [ ] Sensitive attributes (`role`, `admin`, `balance`, `confirmed`) never included in `permit`

### XSS and Output Encoding
- [ ] No `.html_safe` or `raw()` on user-supplied strings
- [ ] `sanitize` used with explicit `tags:` and `attributes:` for user-generated rich HTML
- [ ] All `link_to` hrefs with user data validated for scheme (`http`/`https` only)
- [ ] Content Security Policy configured in production
- [ ] `json_escape` used when rendering JSON in inline `<script>` blocks

### Authentication and Sessions
- [ ] `secret_key_base` stored in environment variable / secrets manager, not in code
- [ ] Session cookie configured with `httponly: true`, `secure: true`, `same_site: :lax`
- [ ] `reset_session` called before setting `session[:user_id]` on login
- [ ] Passwords hashed with BCrypt (`has_secure_password` or `BCrypt::Password.create`)
- [ ] No `MD5` or `SHA1` for password hashing or security-sensitive integrity checks

### Authorization
- [ ] All resource lookups scoped to current user or authorized via Pundit/CanCanCan
- [ ] `before_action :authorize!` (or equivalent) on every sensitive controller action
- [ ] Collection queries use `policy_scope` (Pundit) or equivalent

### Regular Expressions
- [ ] All input-validation regexes use `\A` and `\z`, not `^` and `$`
- [ ] No nested quantifiers on variable-width groups (`/(a+)+/`)
- [ ] User-supplied patterns use `Regexp.escape` before embedding

### Cryptography
- [ ] Unique IV generated per encryption operation with `OpenSSL::Random.random_bytes(12)`
- [ ] AES-256-GCM used for symmetric encryption with authentication tag verified
- [ ] `SecureRandom.hex(32)` or `SecureRandom.urlsafe_base64(32)` for token generation
- [ ] `ActiveSupport::SecurityUtils.secure_compare` for token/HMAC comparison

### Rails Configuration
- [ ] `config.consider_all_requests_local = false` in production
- [ ] `config.filter_parameters` includes all sensitive fields
- [ ] `config.force_ssl = true` in production
- [ ] Default security headers (`X-Frame-Options`, `X-Content-Type-Options`) not removed
- [ ] Open redirect prevention: `redirect_to` targets validated before use

### Supply Chain
- [ ] `Gemfile.lock` committed and reviewed in pull requests
- [ ] `bundler-audit` or `bundle-audit` runs in CI pipeline
- [ ] `bundle update` performed regularly with changelog review for security-relevant gems
- [ ] Devise, Nokogiri, Rails, ActiveSupport versions kept up-to-date with security patches

---

## Tooling

| Tool | Purpose | Command |
|------|---------|---------|
| [bundler-audit](https://github.com/rubysec/bundler-audit) | Checks Gemfile.lock for known CVEs | `bundle exec bundler-audit check --update` |
| [Brakeman](https://brakemanscanner.org/) | Rails static security scanner | `brakeman -A` |
| [RuboCop](https://rubocop.org/) | Ruby linter (security cops via rubocop-rails-security) | `rubocop --require rubocop-rails` |
| [ruby-advisory-db](https://github.com/rubysec/ruby-advisory-db) | Advisory database for Bundler Audit | Updated automatically by `bundler-audit check --update` |
| [Snyk](https://snyk.io/) | Dependency vulnerability scanning | `snyk test` |
| [Semgrep](https://semgrep.dev/) | Pattern-based SAST (Ruby rules available) | `semgrep --config=p/ruby` |
| [OWASP ZAP](https://www.zaproxy.org/) | DAST for Rails web applications | `zap-baseline.py -t https://app.example.com` |
