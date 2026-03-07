---
name: C / C++ Security
description: >
  Activate when writing or reviewing C or C++ code involving gets/strcpy/strcat/sprintf/scanf without size limits,
  malloc/calloc/realloc/free/new/delete memory management, use-after-free or dangling pointers,
  integer overflow or truncation in allocation sizes, printf/fprintf/syslog with non-literal format strings,
  system()/popen() with user input, execve/execvp command execution, access()+open() TOCTOU patterns,
  mkstemp/tmpnam temporary files, reinterpret_cast/dynamic_cast/union type punning, memset on sensitive data
  (use explicit_bzero/memset_s), rand()/random() for security values (use getrandom/arc4random_buf),
  CRYPTO_memcmp/timingsafe_bcmp token comparison, mlock for key material, Path.expand/realpath path traversal,
  compiler flags (stack-protector/PIE/RELRO/FORTIFY_SOURCE/CFI), RAII/unique_ptr/shared_ptr/scoped_lock,
  CMake FetchContent/Conan/vcpkg dependency pinning, or OpenSSL/libsodium cryptographic APIs.
  Also activate when the user mentions buffer overflow, heap overflow, use-after-free, double free, format string,
  integer overflow, TOCTOU, AddressSanitizer, UBSan, Valgrind, cppcheck, checksec, Heartbleed, CVE, or asks
  for a C or C++ security review.
---

## Use this skill when

Activate when writing or reviewing C or C++ code involving gets/strcpy/strcat/sprintf/scanf without size limits,
malloc/calloc/realloc/free/new/delete memory management, use-after-free or dangling pointers,
integer overflow or truncation in allocation sizes, printf/fprintf/syslog with non-literal format strings,
system()/popen() with user input, execve/execvp command execution, access()+open() TOCTOU patterns,
mkstemp/tmpnam temporary files, reinterpret_cast/dynamic_cast/union type punning, memset on sensitive data
(use explicit_bzero/memset_s), rand()/random() for security values (use getrandom/arc4random_buf),
CRYPTO_memcmp/timingsafe_bcmp token comparison, mlock for key material, realpath/openat path traversal,
compiler flags (stack-protector/PIE/RELRO/FORTIFY_SOURCE/CFI), RAII/unique_ptr/shared_ptr/scoped_lock,
CMake FetchContent/Conan/vcpkg dependency pinning, or OpenSSL/libsodium cryptographic APIs.
Also activate when the user mentions buffer overflow, heap overflow, use-after-free, double free, format string,
integer overflow, TOCTOU, AddressSanitizer, UBSan, Valgrind, cppcheck, checksec, Heartbleed, CVE, or asks
for a C or C++ security review.

## Instructions

Read the `rules.md` file in this skill directory and apply those security rules to all code analysis and generation tasks.
