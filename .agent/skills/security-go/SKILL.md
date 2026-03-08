---
name: Go Security
description: >
  Activate when writing or reviewing Go code involving os/exec/exec.Command shell invocation,
  database/sql/GORM/sqlx fmt.Sprintf query building, path/filepath/os.ReadFile with user paths,
  sync.Map/sync.RWMutex/goroutine map access concurrency, http.Server/http.Client missing timeouts,
  crypto/rand/math/rand/bcrypt/AES-GCM/cipher.NewGCM cryptography, text/template vs html/template XSS,
  http.Get/net.Dial SSRF with user URLs, tls.Config InsecureSkipVerify/MinVersion TLS,
  golang-jwt/jwt-go/go-jose JWT parsing, encoding/xml/encoding/json/encoding/gob deserialization,
  http.Redirect open redirect, w.Header().Set CRLF injection, context.WithCancel/WithTimeout goroutine leaks,
  log.Printf/slog sensitive data logging, make() integer overflow allocation,
  regexp.MustCompile with user patterns, go.mod/go.sum/govulncheck supply chain.
  Also activate when the user mentions CVE, Rapid Reset, jwt-go alg confusion, race condition,
  Slowloris, gosec, govulncheck, golangci-lint, go test -race, or asks for a Go security review.
---

## Use this skill when

Activate when writing or reviewing Go code involving os/exec/exec.Command shell invocation,
database/sql/GORM/sqlx fmt.Sprintf query building, path/filepath/os.ReadFile with user paths,
sync.Map/sync.RWMutex/goroutine map access concurrency, http.Server/http.Client missing timeouts,
crypto/rand/math/rand/bcrypt/AES-GCM/cipher.NewGCM cryptography, text/template vs html/template XSS,
http.Get/net.Dial SSRF with user URLs, tls.Config InsecureSkipVerify/MinVersion TLS,
golang-jwt/jwt-go/go-jose JWT parsing, encoding/xml/encoding/json/encoding/gob deserialization,
http.Redirect open redirect, w.Header().Set CRLF injection, context.WithCancel/WithTimeout goroutine leaks,
log.Printf/slog sensitive data logging, make() integer overflow allocation,
regexp.MustCompile with user patterns, go.mod/go.sum/govulncheck supply chain.
Also activate when the user mentions CVE, Rapid Reset, jwt-go alg confusion, race condition,
Slowloris, gosec, govulncheck, golangci-lint, go test -race, or asks for a Go security review.

## Instructions

Read the `rules.md` file in this skill directory and apply those security rules to all code analysis and generation tasks.
