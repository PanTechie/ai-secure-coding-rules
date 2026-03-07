---
name: Ruby Security
description: >
  Activate when writing or reviewing Ruby or Ruby on Rails code involving eval/instance_eval/class_eval/ERB.new,
  send/public_send with dynamic method names, ActiveRecord where/order/group/having/find_by_sql with string
  interpolation, system/exec/spawn/IO.popen/backticks with user input, Marshal.load/Marshal.restore,
  YAML.load (use safe_load), Nokogiri::XML parsing, params.permit!/mass assignment, html_safe/raw/sanitize,
  redirect_to with user-controlled URLs, render file:/render action: with params, File.read/File.open with
  user paths, CarrierWave/ActiveStorage file uploads, BCrypt/OpenSSL/Digest, SecureRandom, session management,
  Pundit/CanCanCan authorization, regex anchors (^ vs \A), bundler-audit, or Gemfile/Gemfile.lock.
  Also activate when the user mentions CVE, Rails security, Brakeman, IDOR, mass assignment, SSTI,
  open redirect, ReDoS, deserialization, or asks for a Ruby or Rails security review.
allowed-tools: Read
---

Read the `rules.md` file in this skill directory and apply those security rules to all code analysis and generation tasks.
