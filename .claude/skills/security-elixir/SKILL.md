---
name: Elixir Security
description: >
  Activate when writing or reviewing Elixir or Phoenix code involving Code.eval_string/EEx.eval_string,
  String.to_atom (use String.to_existing_atom), :erlang.binary_to_term (use [:safe] flag),
  Ecto.Query.fragment/Repo.query with string interpolation, :os.cmd/System.cmd/Port.open with user input,
  File.read/Path.expand with user paths, xmerl/SweetXml XML parsing, :crypto/Bcrypt/Argon2 cryptography,
  Guardian/Pow authentication, Phoenix LiveView handle_event, Plug.CSRFProtection, CORS configuration,
  Phoenix.HTML.raw/raw/html_safe, configure_session, Erlang/OTP SSH or TLS (:ssl module),
  config/runtime.exs secrets management, Logger with sensitive data, Bodyguard/Canada authorization,
  or mix.lock/Hex dependencies.
  Also activate when the user mentions CVE, atom exhaustion, binary_to_term, Sobelow, mix_audit,
  Erlang/OTP vulnerability, OTP SSH, or asks for an Elixir or Phoenix security review.
allowed-tools: Read
---

Read the `rules.md` file in this skill directory and apply those security rules to all code analysis and generation tasks.
