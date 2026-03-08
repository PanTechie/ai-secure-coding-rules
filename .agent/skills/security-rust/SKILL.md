---
name: Rust Security
description: >
  Activate when writing or reviewing Rust code involving unsafe/raw pointers/transmute/Send+Sync,
  integer overflow/checked_add/checked_mul/TryFrom arithmetic, std::process::Command shell invocation,
  diesel/sqlx/sea-orm SQL query building, std::fs::File/canonicalize path traversal,
  serde/bincode/ciborium/postcard deserialization, ring/RustCrypto/rand/OsRng/AES-GCM cryptography,
  rustls/native-tls/reqwest TLS configuration, reqwest/hyper SSRF with user URLs,
  unwrap/expect panic safety, tokio/std::sync::Mutex/RwLock concurrency,
  regex/fancy-regex ReDoS, std::ffi/CString FFI interop, axum/actix-web/warp web framework security,
  tracing/log sensitive data logging, cargo/Cargo.lock/cargo-audit supply chain.
  Also activate when the user mentions CVE, RustSec, RUSTSEC advisory, cargo audit, cargo-deny,
  unsafe soundness, use-after-free, integer overflow, nonce reuse, poisoned mutex,
  cargo-geiger, cargo-fuzz, or asks for a Rust security review.
---

## Use this skill when

Activate when writing or reviewing Rust code involving unsafe/raw pointers/transmute/Send+Sync,
integer overflow/checked_add/checked_mul/TryFrom arithmetic, std::process::Command shell invocation,
diesel/sqlx/sea-orm SQL query building, std::fs::File/canonicalize path traversal,
serde/bincode/ciborium/postcard deserialization, ring/RustCrypto/rand/OsRng/AES-GCM cryptography,
rustls/native-tls/reqwest TLS configuration, reqwest/hyper SSRF with user URLs,
unwrap/expect panic safety, tokio/std::sync::Mutex/RwLock concurrency,
regex/fancy-regex ReDoS, std::ffi/CString FFI interop, axum/actix-web/warp web framework security,
tracing/log sensitive data logging, cargo/Cargo.lock/cargo-audit supply chain.
Also activate when the user mentions CVE, RustSec, RUSTSEC advisory, cargo audit, cargo-deny,
unsafe soundness, use-after-free, integer overflow, nonce reuse, poisoned mutex,
cargo-geiger, cargo-fuzz, or asks for a Rust security review.

## Instructions

Read the `rules.md` file in this skill directory and apply those security rules to all code analysis and generation tasks.
