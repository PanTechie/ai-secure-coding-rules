---
name: Clojure Security
description: >
  Detailed security rules for Clojure 1.11+ on the JVM, including Ring/Compojure and next.jdbc.
  Activate when writing or reviewing Clojure code involving eval/read-string/load-string/load-file,
  nREPL/clojure.main/repl, clojure.edn/read-string vs core read-string, next.jdbc/execute!/query,
  clojure.java.jdbc, ring.middleware/wrap-defaults/wrap-session/wrap-anti-forgery,
  compojure/defroutes/context, clojure.java.shell/sh, clojure.java.io/file,
  nippy/thaw, transit-clj/read, buddy-hashers/bcrypt, timbre logging, lein-nvd,
  clj-watson, or deps.edn/Leiningen supply chain.
  Also activate when the user mentions CVE, code injection, nREPL exposure, EDN deserialization,
  CSRF in Ring, ReDoS, or asks for a Clojure security review.
---

## Use this skill when

Activate when writing or reviewing Clojure code involving eval/read-string/load-string/load-file, nREPL/clojure.main/repl, clojure.edn/read-string vs core read-string, next.jdbc/execute!/query, clojure.java.jdbc, ring.middleware/wrap-defaults/wrap-session/wrap-anti-forgery, compojure/defroutes/context, clojure.java.shell/sh, clojure.java.io/file, nippy/thaw, transit-clj/read, buddy-hashers/bcrypt, timbre logging, lein-nvd, clj-watson, or deps.edn/Leiningen supply chain. Also activate when the user mentions CVE, code injection, nREPL exposure, EDN deserialization, CSRF in Ring, ReDoS, or asks for a Clojure security review.

## Instructions

Read the `rules.md` file in this skill directory and apply those security rules to all code analysis and generation tasks.
