# ⚙️ C / C++ Security Rules

> **Standard:** Security rules for C (C11/C17) and C++ (C++17/C++20), covering memory safety, undefined behavior, dangerous standard library functions, and compiler hardening.
> **Sources:** SEI CERT C/C++ Coding Standard, MISRA C:2023, CWE/MITRE, NIST NVD, Google Project Zero, OpenSSL Security Advisories, OWASP, Clang/GCC security documentation
> **Version:** 1.0.0
> **Last updated:** March 2026
> **Scope:** C11/C17 and C++17/C++20 with GCC/Clang toolchains. Linux/POSIX primary target; Windows-specific APIs noted where relevant. Embedded/bare-metal Annex K (_s functions) noted but not the primary focus.

---

## General Instructions

Apply these rules when writing or reviewing C or C++ code. C and C++ offer maximum performance and control at the cost of memory safety — the language provides no automatic bounds checking, no garbage collection, and no protection against undefined behavior. The vast majority of critical vulnerabilities (buffer overflows, use-after-free, format string bugs, integer overflows) stem from trusting the programmer to manage memory and sizes correctly. Prefer modern C++ idioms (RAII, smart pointers, `std::span`, `std::string_view`, containers) over raw pointer arithmetic. Always enable compiler hardening flags in production builds and run sanitizers (ASan, UBSan, MSan) in CI.

---

## 1. Buffer Overflow — Dangerous C Standard Library Functions

**Vulnerability:** Functions that do not take a buffer size argument (`gets`, `strcpy`, `strcat`, `sprintf`, `scanf("%s")`) write beyond allocated memory when input exceeds the buffer. Stack buffer overflows allow overwriting the return address; heap buffer overflows corrupt allocator metadata or adjacent objects.

**References:** CWE-121, CWE-122, CWE-119, CVE-2021-3156 (sudo heap overflow), CVE-2023-4911 (glibc ld.so), SEI CERT STR31-C

### Mandatory Rules

- **Never use `gets()`** — it was removed in C11 and C++14 for good reason; replace with `fgets(buf, sizeof(buf), stdin)`.
- **Never use `strcpy()` or `strcat()` with user-controlled source** — use `strlcpy()`/`strlcat()` (BSD/glibc) or `strncpy()`+explicit null termination, or `std::string` in C++.
- **Never use `sprintf()` with a format string containing `%s` and user input** — use `snprintf(buf, sizeof(buf), "%s", user_input)` with explicit size.
- **Never use `scanf("%s", buf)`** — always include a width limit: `scanf("%255s", buf)` where 255 = `sizeof(buf) - 1`.
- **In C++, prefer `std::string`, `std::array`, and `std::vector`** over fixed-size C arrays for string and buffer management.
- **Use `std::span<T>` (C++20) or `gsl::span`** to pass buffer + size as a single parameter, preventing size/buffer mismatches.

```c
/* ❌ INSECURE — gets(): no bounds check, always vulnerable */
char buf[64];
gets(buf);

/* ❌ INSECURE — strcpy: no size check */
char dest[64];
strcpy(dest, user_input);

/* ❌ INSECURE — sprintf: buffer overflow on long format */
char msg[128];
sprintf(msg, "Hello, %s!", user_name);

/* ✅ SECURE — fgets with explicit size */
char buf[64];
if (fgets(buf, sizeof(buf), stdin) == NULL) { /* handle EOF/error */ }
buf[strcspn(buf, "\n")] = '\0';  /* strip newline */

/* ✅ SECURE — snprintf with explicit size */
char msg[128];
snprintf(msg, sizeof(msg), "Hello, %s!", user_name);

/* ✅ SECURE — strlcpy (null-terminates, returns needed length) */
if (strlcpy(dest, user_input, sizeof(dest)) >= sizeof(dest)) {
    /* truncation occurred — handle */
}
```

```cpp
// ✅ SECURE — C++: use std::string and avoid fixed buffers
std::string greeting = "Hello, " + std::string(user_name) + "!";

// ✅ SECURE — C++20: std::span enforces bounds
void process(std::span<const char> data) {
    for (char c : data) { /* bounds-safe iteration */ }
}
```

---

## 2. Use-After-Free and Dangling Pointers

**Vulnerability:** Accessing memory after it has been freed (use-after-free) or through a pointer to a destroyed object (dangling pointer) causes undefined behavior — typically exploitable as type confusion, code execution, or information disclosure. Modern exploits chain heap grooming with use-after-free for reliable RCE.

**References:** CWE-416, CWE-415 (double free), CVE-2021-28041 (OpenSSH double-free), CVE-2021-20226 (io_uring UAF), SEI CERT MEM30-C

### Mandatory Rules

- **In C: set pointers to `NULL` immediately after `free()`** — prevents double-free and makes dangling pointer access detectable.
- **In C++: prefer `std::unique_ptr` and `std::shared_ptr` over raw `new`/`delete`** — RAII ensures deallocation exactly once when the owner goes out of scope.
- **Never use a raw pointer after ownership has been transferred** — use `std::move` to signal transfer; the source `unique_ptr` becomes null automatically.
- **Never store raw pointers to objects whose lifetime you do not control** — use `std::weak_ptr` to observe `shared_ptr`-managed objects without extending their lifetime.
- **Never return a pointer or reference to a local (stack) variable** — it becomes dangling immediately on function return.
- **Never use iterators, references, or pointers into a container after the container is modified** — reallocation invalidates all iterators.

```c
/* ❌ INSECURE — use-after-free */
char *buf = malloc(64);
free(buf);
memcpy(buf, user_data, 64);  /* undefined behavior: UAF */

/* ❌ INSECURE — double free */
free(buf);
free(buf);  /* heap corruption */

/* ✅ SECURE — NULL after free; check before use */
free(buf);
buf = NULL;

/* ✅ SECURE — guard against double-free */
if (buf != NULL) {
    free(buf);
    buf = NULL;
}
```

```cpp
// ❌ INSECURE — dangling reference to local
const char* get_name() {
    std::string name = "Alice";
    return name.c_str();  // name destroyed, pointer dangles
}

// ✅ SECURE — unique_ptr: automatic deallocation
auto buf = std::make_unique<char[]>(64);
// ... use buf.get() ...
// automatically freed when buf goes out of scope

// ✅ SECURE — shared_ptr + weak_ptr observer pattern
auto resource = std::make_shared<Resource>();
std::weak_ptr<Resource> observer = resource;
if (auto locked = observer.lock()) {
    locked->use();  // safe: resource still alive
}
```

---

## 3. Integer Overflow and Truncation

**Vulnerability:** Signed integer overflow is **undefined behavior** in C/C++ — the compiler may eliminate checks, reorder code, or produce incorrect results. Unsigned overflow wraps silently. Integer truncation on cast (e.g., `size_t` → `int`) is a common source of allocation size miscalculation leading to heap underallocation and subsequent overflow.

**References:** CWE-190, CWE-191, CWE-195, CVE-2002-0083 (OpenSSH integer overflow RCE), SEI CERT INT30-C, INT31-C, INT32-C

### Mandatory Rules

- **Never compute allocation sizes with potentially overflowing arithmetic** — check for overflow before multiplying: `if (count > SIZE_MAX / elem_size) { /* overflow */ }`.
- **Use `size_t` for sizes and counts** — never `int` or `unsigned int`; they can truncate on 64-bit systems.
- **Check for overflow before arithmetic on signed integers** — use `__builtin_add_overflow`, `__builtin_mul_overflow` (GCC/Clang) or `<stdckdint.h>` (C23).
- **Never silently truncate `size_t` to `int`** — if a cast is necessary, validate the value fits in the target type first.
- **Use `ptrdiff_t` for pointer arithmetic differences** — it is the correct signed type for the difference between two pointers.
- **Enable `-ftrapv`** in debug builds to trap signed integer overflow at runtime.

```c
/* ❌ INSECURE — integer overflow in allocation: count * size overflows */
void *buf = malloc(count * elem_size);  /* if count * elem_size > SIZE_MAX: wraps to small allocation */

/* ❌ INSECURE — size_t truncated to int: sign mismatch / truncation */
size_t len = strlen(user_input);
char *buf = malloc(len + 1);
memcpy(buf, user_input, (int)len);  /* (int) may truncate if len > INT_MAX */

/* ✅ SECURE — checked multiplication before allocation */
if (count != 0 && elem_size > SIZE_MAX / count) {
    return NULL;  /* would overflow */
}
void *buf = malloc(count * elem_size);

/* ✅ SECURE — GCC/Clang built-in overflow check */
size_t total;
if (__builtin_mul_overflow(count, elem_size, &total)) {
    return NULL;
}
void *buf = malloc(total);

/* ✅ SECURE — C23 checked arithmetic */
#include <stdckdint.h>
size_t total;
if (ckd_mul(&total, count, elem_size)) {
    return NULL;
}
```

---

## 4. Format String Vulnerabilities

**Vulnerability:** Passing user-controlled data as the format string argument to `printf`, `fprintf`, `sprintf`, `syslog`, `err`, or `warn` allows an attacker to read arbitrary stack memory (`%x`, `%s`), write to arbitrary memory addresses (`%n`), or crash the process. This is a direct exploitation primitive.

**References:** CWE-134, CVE-2012-0809 (sudo format string), OWASP Format String Attack, SEI CERT FIO30-C

### Mandatory Rules

- **Never pass user-controlled data as the format string** — always use a literal format string: `printf("%s", user_data)` not `printf(user_data)`.
- **Always use `printf("%s\n", msg)` not `printf(msg)`** even when `msg` seems safe — a future code change may make it attacker-controlled.
- **Apply `-Wformat -Wformat-security -Werror=format-security`** compiler flags — these warn on non-literal format strings.
- **For `syslog()`**, always use: `syslog(LOG_INFO, "%s", user_message)`.
- **In C++, use `std::format` (C++20) or `{fmt}` library** over `printf`-family functions — type-safe and not susceptible to format string attacks.

```c
/* ❌ INSECURE — format string from user input */
printf(user_input);
fprintf(log_file, user_input);
syslog(LOG_ERR, user_input);

/* ✅ SECURE — literal format string */
printf("%s", user_input);
fprintf(log_file, "%s\n", user_input);
syslog(LOG_ERR, "%s", user_input);
```

```cpp
// ✅ SECURE — C++20 std::format: type-safe, no format string injection
#include <format>
std::string msg = std::format("Hello, {}!", user_name);
std::cout << msg;
```

---

## 5. Uninitialized Memory and Information Disclosure

**Vulnerability:** Using uninitialized local variables or uninitialized heap memory reads whatever bytes happen to be at that address — potentially sensitive data from a previous allocation (keys, passwords, tokens). Stack structures with padding bytes also disclose kernel/stack data when copied to user space or network.

**References:** CWE-457, CWE-908, CVE-2014-9295 (NTP stack disclosure), SEI CERT EXP33-C

### Mandatory Rules

- **Initialize all local variables at declaration** — `int n = 0;`, `char buf[64] = {0};`, `struct foo s = {0};`.
- **Use `calloc()` instead of `malloc()` when the buffer must be zeroed** — calloc initializes to zero and checks for overflow in the multiplication.
- **Zero-initialize C++ objects with `= {}` or `= {0}`** when the default constructor does not initialize all fields.
- **Zero structure padding explicitly** — `memset(&s, 0, sizeof(s))` before copying a struct to the network or user space.
- **Enable `-Wuninitialized` and `-Wmaybe-uninitialized`** — compiler warnings catch many (but not all) uninitialized reads.
- **Run `valgrind --track-origins=yes` or MemorySanitizer (`-fsanitize=memory`)** in CI to detect all uninitialized reads.

```c
/* ❌ INSECURE — uninitialized stack variable */
int result;
if (condition) result = compute();
send_to_client(&result, sizeof(result));  /* may send uninitialized bytes */

/* ❌ INSECURE — uninitialized struct with padding */
struct Response { uint8_t type; uint32_t value; };  /* 3 bytes padding before value */
struct Response r;
r.type = 1; r.value = 42;
send(sock, &r, sizeof(r), 0);  /* padding bytes leak stack data */

/* ✅ SECURE — initialize at declaration */
int result = 0;

/* ✅ SECURE — zero entire struct including padding */
struct Response r = {0};
r.type = 1; r.value = 42;
send(sock, &r, sizeof(r), 0);

/* ✅ SECURE — calloc zeros memory */
char *buf = calloc(count, elem_size);  /* also checks count * elem_size overflow */
```

---

## 6. Null Pointer Dereference

**Vulnerability:** `malloc`, `calloc`, `realloc`, `fopen`, `strdup`, and many POSIX functions return `NULL` on failure. Dereferencing `NULL` is undefined behavior — on most systems it causes a segfault (DoS), but on systems without memory protection it can corrupt memory.

**References:** CWE-476, SEI CERT EXP34-C

### Mandatory Rules

- **Always check the return value of `malloc`, `calloc`, `realloc`, `strdup`, `fopen`, and similar allocation functions** before use.
- **Always check `realloc` separately** — on failure it returns `NULL` but does NOT free the original pointer; reassigning the original pointer loses it, causing a memory leak.
- **In C++, prefer `std::make_unique`, `std::make_shared`, and containers** — they throw `std::bad_alloc` on failure rather than returning `NULL`.
- **Enable `-Wnull-dereference`** compiler flag.
- **Never cast `NULL` to a non-pointer type** and dereference it.

```c
/* ❌ INSECURE — no NULL check: crash or UB if allocation fails */
char *buf = malloc(size);
memcpy(buf, src, size);

/* ❌ INSECURE — realloc misuse: leak on failure */
buf = realloc(buf, new_size);  /* if realloc returns NULL, original buf is leaked */
buf[0] = 0;                    /* NULL dereference */

/* ✅ SECURE — check malloc return */
char *buf = malloc(size);
if (buf == NULL) {
    perror("malloc");
    return -1;
}
memcpy(buf, src, size);
free(buf);

/* ✅ SECURE — realloc with temporary */
char *tmp = realloc(buf, new_size);
if (tmp == NULL) {
    free(buf);   /* original still valid; free it */
    return -1;
}
buf = tmp;
```

---

## 7. Command Injection

**Vulnerability:** `system()` and `popen()` pass their argument to the shell (`/bin/sh -c`), enabling command injection via shell metacharacters. `execve()` and `execvp()` with a list of arguments bypass the shell and are safe, but the executable path must still be validated.

**References:** CWE-78, OWASP Command Injection, SEI CERT ENV33-C

### Mandatory Rules

- **Never use `system()` or `popen()` with user-controlled input** — they always invoke a shell.
- **Use `execve()` or `execvp()` with an argument array** — never pass a single shell string.
- **Use `posix_spawn()` as a safer alternative** to `fork()`+`execve()` in multi-threaded programs.
- **Allowlist all values** used as arguments to `execve` — even without a shell, argument injection can affect some programs.
- **Validate the executable path** — use an absolute path, never a PATH-relative name.
- **In C++: use a subprocess library** (e.g., `boost::process`, `reproc`) rather than raw `system()`.

```c
/* ❌ INSECURE — system() with user input: shell injection */
char cmd[256];
snprintf(cmd, sizeof(cmd), "convert %s output.png", user_filename);
system(cmd);  /* user_filename = "foo.jpg; rm -rf /" */

/* ❌ INSECURE — popen with user input */
FILE *f = popen(user_command, "r");

/* ✅ SECURE — execve with argument array (no shell) */
pid_t pid = fork();
if (pid == 0) {
    /* child */
    char *argv[] = {"/usr/bin/convert", user_filename, "output.png", NULL};
    execve("/usr/bin/convert", argv, NULL);
    _exit(1);  /* execve failed */
}
int status;
waitpid(pid, &status, 0);
```

---

## 8. Race Conditions — TOCTOU (Time-of-Check-to-Time-of-Use)

**Vulnerability:** Checking a file's properties (existence, permissions, ownership) with `access()`, `stat()`, or `lstat()` and then opening it with `open()` creates a race window. An attacker with filesystem access can swap the file between the check and the open (symlink attack), causing the operation to affect a different file than intended.

**References:** CWE-367, CWE-362, CVE-2004-0230, CVE-2021-4034 (pkexec argv processing race), SEI CERT FIO45-C

### Mandatory Rules

- **Never use `access()` to check permissions before `open()`** — use `open()` directly and let the kernel reject unauthorized access via `errno`.
- **Use `openat()` with `O_NOFOLLOW`** to prevent symlink traversal — prevents following symlinks in the last path component.
- **Use `O_CREAT | O_EXCL` for exclusive file creation** — atomically creates the file and fails if it already exists.
- **Use `fstat()` on the opened file descriptor** rather than `stat()` on the path — checks the actual opened file, not a potentially different one.
- **In multi-threaded code, protect shared mutable state with mutexes** — `std::mutex` in C++, `pthread_mutex_t` in C.
- **Use `lockf()` or `flock()` for file-level locking** when multiple processes access the same file.

```c
/* ❌ INSECURE — TOCTOU: symlink swap between access() and open() */
if (access(path, R_OK) == 0) {
    int fd = open(path, O_RDONLY);   /* different file may be here now */
    /* ... */
}

/* ✅ SECURE — open directly; let kernel enforce permissions */
int fd = open(path, O_RDONLY | O_NOFOLLOW);
if (fd < 0) {
    perror("open");
    return -1;
}
/* verify it's the expected file type after open */
struct stat st;
fstat(fd, &st);  /* fstat on fd, not stat on path */
if (!S_ISREG(st.st_mode)) {
    close(fd);
    return -1;
}

/* ✅ SECURE — exclusive file creation */
int fd = open(tmpfile, O_CREAT | O_EXCL | O_WRONLY, 0600);
if (fd < 0) {
    /* file already exists or error */
}
```

---

## 9. Type Safety — C++ Casts and Undefined Behavior

**Vulnerability:** C-style casts and `reinterpret_cast` bypass the type system, potentially violating strict aliasing rules (UB), truncating values, or treating one type's memory layout as another. `dynamic_cast` without null-check crashes on failure. Type punning via unions is only legal in C, not C++ (strict aliasing violation).

**References:** CWE-843 (type confusion), SEI CERT EXP39-C, CERT OOP50-CPP

### Mandatory Rules

- **Prefer C++-style named casts** (`static_cast`, `dynamic_cast`, `const_cast`, `reinterpret_cast`) over C-style casts — they make intent explicit and are easier to audit.
- **Check the result of `dynamic_cast<T*>`** before dereferencing — returns `nullptr` on failure.
- **Never use `reinterpret_cast` to convert between incompatible pointer types** and then dereference — violates strict aliasing (UB); use `memcpy` for type-punning in C++.
- **Never use unions for type punning in C++** — use `std::bit_cast<T>` (C++20) or `memcpy` into a local variable.
- **Avoid `const_cast` to remove `const` from a genuinely const object** — writing to a `const` object is undefined behavior.
- **Use `std::variant` instead of `void*` or union-based tagged unions** — type-safe discriminated union.

```cpp
// ❌ INSECURE — C-style cast: silently wrong
double d = 3.14;
int *p = (int*)&d;      // strict aliasing violation: UB
std::cout << *p;

// ❌ INSECURE — dynamic_cast without null check
Base *base = get_object();
Derived *derived = dynamic_cast<Derived*>(base);
derived->method();   // crash if base is not a Derived

// ❌ INSECURE — union type punning (C++ strict aliasing UB)
union { float f; uint32_t i; } u;
u.f = 3.14f;
uint32_t bits = u.i;   // UB in C++

// ✅ SECURE — dynamic_cast with null check
Derived *derived = dynamic_cast<Derived*>(base);
if (derived == nullptr) {
    throw std::bad_cast{};
}
derived->method();

// ✅ SECURE — std::bit_cast (C++20): defined behavior
uint32_t bits = std::bit_cast<uint32_t>(3.14f);

// ✅ SECURE — memcpy for type punning (defined in all versions)
float f = 3.14f;
uint32_t bits;
std::memcpy(&bits, &f, sizeof(bits));

// ✅ SECURE — std::variant instead of tagged union
std::variant<int, double, std::string> value = 42;
if (auto *n = std::get_if<int>(&value)) {
    std::cout << *n;
}
```

---

## 10. Cryptographic Memory Zeroization

**Vulnerability:** Sensitive data (passwords, keys, tokens) stored in memory must be explicitly zeroed before the buffer is freed or reused. Compilers may optimize away `memset()` calls on buffers that are not subsequently read — the sensitive data persists in memory and can be extracted from swap files, crash dumps, or via cold-boot attacks.

**References:** CWE-316, CWE-226, SEI CERT MSC06-C, OWASP Cryptographic Failures

### Mandatory Rules

- **Never use `memset()` alone to zero sensitive buffers** — it may be optimized away; use `explicit_bzero()` (POSIX 2017, glibc, OpenBSD) or `memset_s()` (C11 Annex K) or `SecureZeroMemory()` (Windows).
- **Zero sensitive data as early as possible** — immediately before `free()` or when the variable goes out of scope.
- **In C++, use `OPENSSL_cleanse()` or a `SecureBuffer` RAII wrapper** that zeros memory in its destructor.
- **Use `mlock()` / `VirtualLock()` for highly sensitive buffers** (master keys, private keys) to prevent them from being swapped to disk.
- **Never log, serialize, or copy raw sensitive data** (passwords, private keys, session tokens) unnecessarily.

```c
/* ❌ INSECURE — memset may be optimized away by the compiler */
void process_password(const char *input) {
    char password[64];
    strncpy(password, input, sizeof(password) - 1);
    authenticate(password);
    memset(password, 0, sizeof(password));  /* compiler may remove this */
}

/* ✅ SECURE — explicit_bzero is not optimized away */
void process_password(const char *input) {
    char password[64];
    strncpy(password, input, sizeof(password) - 1);
    password[sizeof(password) - 1] = '\0';
    authenticate(password);
    explicit_bzero(password, sizeof(password));  /* guaranteed to execute */
}

/* ✅ SECURE — memset_s (C11 Annex K, also available as __memset_s on some platforms) */
memset_s(password, sizeof(password), 0, sizeof(password));
```

```cpp
// ✅ SECURE — C++ RAII wrapper that zeros on destruction
template<std::size_t N>
struct SecureBuffer {
    std::array<char, N> data{};
    ~SecureBuffer() { explicit_bzero(data.data(), data.size()); }
    char* get() { return data.data(); }
};
```

---

## 11. Cryptographic Randomness

**Vulnerability:** The C standard `rand()` function is a pseudo-random number generator with small state, predictable output, and is seeded with `time()` by default — trivially predictable for an attacker who knows the approximate start time. Using `rand()` for security-sensitive purposes (nonces, tokens, keys, IVs) is a critical vulnerability.

**References:** CWE-338, CWE-330, OWASP Cryptographic Failures, SEI CERT MSC30-C

### Mandatory Rules

- **Never use `rand()`, `random()`, or `drand48()` for security-sensitive values** — use OS-provided CSPRNG.
- **Use `getrandom(buf, len, 0)` (Linux 3.17+) or `/dev/urandom`** for cryptographic randomness in C.
- **Use `arc4random_buf()` on macOS/BSD** — it wraps the system CSPRNG and never blocks.
- **In C++, use `std::random_device`** for seeding or direct use when hardware entropy is available; verify it does not fall back to a PRNG on the target platform.
- **For cryptographic operations, use a vetted library** (libsodium, OpenSSL) — it handles CSPRNG correctly.
- **Use constant-time comparison for tokens** — `timingsafe_bcmp()` (BSD) or `CRYPTO_memcmp()` (OpenSSL) — never `memcmp()` or `strcmp()` for security tokens.

```c
/* ❌ INSECURE — rand() with time() seed: predictable */
srand(time(NULL));
int token = rand();

/* ❌ INSECURE — /dev/random may block indefinitely; use /dev/urandom */
/* /dev/urandom is safe after initial boot entropy seeding */

/* ✅ SECURE — getrandom() (Linux 3.17+) */
#include <sys/random.h>
uint8_t key[32];
if (getrandom(key, sizeof(key), 0) != sizeof(key)) {
    /* handle error */
}

/* ✅ SECURE — /dev/urandom */
FILE *f = fopen("/dev/urandom", "rb");
if (f == NULL || fread(token_buf, 1, sizeof(token_buf), f) != sizeof(token_buf)) {
    /* handle error */
}
fclose(f);

/* ✅ SECURE — libsodium (preferred for new code) */
#include <sodium.h>
randombytes_buf(key, sizeof(key));  /* always cryptographically secure */

/* ✅ SECURE — constant-time comparison */
if (CRYPTO_memcmp(received_token, expected_token, TOKEN_LEN) != 0) {
    return AUTH_FAILURE;
}
```

---

## 12. Heap Management — Allocation Mismatches and Double Free

**Vulnerability:** Mixing `malloc`/`free` with `new`/`delete`, using scalar `delete` for array allocations (`delete[]`), or calling `free()` on a stack-allocated pointer are all undefined behavior causing heap corruption. In C++, mismatched allocation/deallocation is exploitable.

**References:** CWE-590, CWE-415, CWE-762, SEI CERT MEM51-CPP

### Mandatory Rules

- **Always match allocation with the correct deallocation** — `malloc`→`free`, `new`→`delete`, `new[]`→`delete[]`, never mix them.
- **Never call `free()` on a pointer not returned by `malloc`/`calloc`/`realloc`** — stack variables, global arrays, or string literals must not be freed.
- **In C++, prefer `std::make_unique`/`std::make_shared`** over raw `new` — eliminates the risk of mismatched `delete`.
- **Use containers (`std::vector`, `std::string`)** instead of manual heap allocation for dynamic arrays.
- **Never call `delete` or `free` in a destructor if you also use smart pointers** for the same resource — double free.
- **Enable AddressSanitizer** (`-fsanitize=address`) in development and CI to catch heap misuse.

```cpp
// ❌ INSECURE — array allocated with new[], freed with delete (scalar)
int *arr = new int[64];
delete arr;    // UB: should be delete[]

// ❌ INSECURE — mixing malloc and delete
int *p = (int*)malloc(sizeof(int));
delete p;      // UB: must use free()

// ❌ INSECURE — free of stack pointer
char buf[64];
free(buf);     // UB: stack-allocated

// ✅ SECURE — new[] with delete[]
int *arr = new int[64];
delete[] arr;

// ✅ SECURE — prefer smart pointers
auto arr = std::make_unique<int[]>(64);
// automatically deleted as delete[] when arr goes out of scope

// ✅ SECURE — prefer containers
std::vector<int> arr(64, 0);
// no manual memory management required
```

---

## 13. Path Traversal and File Operations

**Vulnerability:** Constructing file paths from user input enables directory traversal (`../../etc/shadow`). Symlink following allows privilege escalation when a privileged process operates on files in user-controlled directories. `realpath()` is the standard canonicalization function but has edge cases.

**References:** CWE-22, CWE-59, CVE-2021-4034 (pkexec path traversal), SEI CERT FIO02-C

### Mandatory Rules

- **Canonicalize all file paths with `realpath()`** and verify the result starts with the expected base directory before any file operation.
- **Use `open()` with `O_NOFOLLOW`** to reject symlinks in the final path component.
- **Use `openat()` with a trusted directory file descriptor** to confine file access to a specific subtree.
- **Strip directory components** from user-supplied filenames with `basename()` (POSIX) before joining with a base path.
- **Never construct paths by string concatenation with unchecked user input** — use explicit canonicalization.
- **Use `mkstemp()` for temporary files** — never `tmpnam()` or `tempnam()` (TOCTOU vulnerable).

```c
/* ❌ INSECURE — path traversal: user can supply ../../etc/passwd */
char path[PATH_MAX];
snprintf(path, sizeof(path), "/var/uploads/%s", user_filename);
int fd = open(path, O_RDONLY);

/* ✅ SECURE — canonicalize and verify prefix */
#define BASE_DIR "/var/uploads"
char resolved[PATH_MAX];
char composed[PATH_MAX];
snprintf(composed, sizeof(composed), "%s/%s", BASE_DIR, basename(user_filename));

if (realpath(composed, resolved) == NULL) {
    return -1;  /* path does not exist or resolution failed */
}
if (strncmp(resolved, BASE_DIR, strlen(BASE_DIR)) != 0 ||
    resolved[strlen(BASE_DIR)] != '/') {
    errno = EACCES;
    return -1;  /* traversal detected */
}
int fd = open(resolved, O_RDONLY | O_NOFOLLOW);

/* ✅ SECURE — mkstemp for temporary files */
char tmpfile[] = "/tmp/myapp-XXXXXX";
int fd = mkstemp(tmpfile);
if (fd < 0) { perror("mkstemp"); return -1; }
unlink(tmpfile);  /* unlink so file is removed on close */
```

---

## 14. Compiler Hardening Flags

**Vulnerability:** Without hardening flags, exploitation of memory safety bugs is easier — no stack canaries means undetected stack smashing, no ASLR means fixed addresses, no RELRO means overwriting GOT pointers. Modern exploits are significantly harder with all mitigations enabled.

**References:** OWASP Proactive Controls, CIS Benchmarks, Linux Kernel hardening documentation

### Mandatory Rules

- **Enable stack protector** — `-fstack-protector-strong` (GCC/Clang) in all production builds.
- **Enable position-independent executable** — `-fPIE -pie` for executables, `-fPIC` for shared libraries; required for ASLR to be effective.
- **Enable RELRO and BIND_NOW** — `-Wl,-z,relro -Wl,-z,now` makes the GOT read-only after startup, preventing GOT overwrite attacks.
- **Enable `_FORTIFY_SOURCE=3`** — adds compile-time and runtime bounds checking for many libc functions: `-D_FORTIFY_SOURCE=3 -O2`.
- **Enable Control Flow Integrity** — `-fsanitize=cfi` (Clang) limits indirect call targets to legitimate function pointers.
- **Run AddressSanitizer, UBSan, and MemorySanitizer in CI** — `-fsanitize=address,undefined` catches memory errors, undefined behavior, and uninitialized reads.
- **Enable all warnings and treat as errors** — `-Wall -Wextra -Werror -Wpedantic` in development builds.

```makefile
# ✅ SECURE — production hardening flags (GCC/Clang)
CFLAGS   = -O2 -Wall -Wextra -Wpedantic -Werror \
           -fstack-protector-strong \
           -fPIE \
           -D_FORTIFY_SOURCE=3 \
           -Wformat -Wformat-security \
           -Wnull-dereference \
           -Wuninitialized

LDFLAGS  = -pie \
           -Wl,-z,relro \
           -Wl,-z,now \
           -Wl,-z,noexecstack

# ✅ SECURE — CI sanitizer build (separate from production)
CFLAGS_ASAN = -O1 -g -fsanitize=address,undefined -fno-omit-frame-pointer
CFLAGS_MSAN = -O1 -g -fsanitize=memory -fno-omit-frame-pointer

# ✅ SECURE — Clang CFI (requires LTO)
CFLAGS_CFI  = -flto -fsanitize=cfi -fvisibility=hidden
LDFLAGS_CFI = -flto -fsanitize=cfi
```

---

## 15. C++ Exception Safety and RAII

**Vulnerability:** Code that acquires resources (memory, file descriptors, locks, network sockets) and then throws an exception before releasing them causes resource leaks. In security-sensitive contexts, leaked file descriptors can be inherited by child processes, and leaked memory can be accessed after the object is logically destroyed.

**References:** CWE-404, CWE-772, SEI CERT ERR56-CPP, C++ Core Guidelines E.6

### Mandatory Rules

- **Use RAII for all resource acquisition** — wrap file descriptors, locks, and dynamic memory in classes whose destructors release the resource; or use `std::unique_ptr` with a custom deleter.
- **Prefer `std::lock_guard` or `std::scoped_lock` over manual `mutex.lock()`/`mutex.unlock()`** — automatically unlocks on exception or early return.
- **Mark functions `noexcept` only when they truly cannot throw** — incorrect `noexcept` causes `std::terminate()` if an exception propagates through it.
- **Use `std::filesystem` (C++17) for file operations** — it uses RAII and throws `std::filesystem::filesystem_error` consistently.
- **Never `throw` in a destructor** — destructors called during stack unwinding must be `noexcept`; throwing causes `std::terminate()`.

```cpp
// ❌ INSECURE — resource leak if exception thrown between open and close
FILE *f = fopen(path, "r");
process(f);      // may throw
fclose(f);       // never reached on exception

// ❌ INSECURE — mutex leak on exception
mtx.lock();
do_work();       // may throw
mtx.unlock();    // never reached

// ✅ SECURE — RAII wrapper for FILE*
struct FileGuard {
    FILE *f;
    explicit FileGuard(const char *path, const char *mode)
        : f(fopen(path, mode)) {
        if (!f) throw std::system_error(errno, std::generic_category());
    }
    ~FileGuard() { if (f) fclose(f); }
    FileGuard(const FileGuard&) = delete;
    FileGuard& operator=(const FileGuard&) = delete;
};

FileGuard guard(path, "r");  // automatically closed on any exit path

// ✅ SECURE — unique_ptr with custom deleter for C resources
auto f = std::unique_ptr<FILE, decltype(&fclose)>(fopen(path, "r"), fclose);
if (!f) throw std::system_error(errno, std::generic_category());

// ✅ SECURE — scoped_lock for mutex
{
    std::scoped_lock lock(mtx);
    do_work();   // lock released automatically on exception or return
}
```

---

## 16. Supply Chain and Build Security

**Vulnerability:** Third-party C/C++ dependencies (Conan, vcpkg, CMake FetchContent) introduce code that runs with full native privileges. Unpinned dependencies, missing checksum verification, and include path injection allow supply chain attacks — including the XZ Utils backdoor (CVE-2024-3094) which targeted the build system of a widely used compression library.

**References:** CWE-1104, CVE-2024-3094 (XZ Utils backdoor), OWASP Supply Chain, CISA Supply Chain Security

### Mandatory Rules

- **Pin all dependencies to exact versions with cryptographic checksums** — Conan lockfiles, vcpkg baselines, CMake FetchContent with `GIT_TAG` SHA and `HASH` verification.
- **Audit build system inputs** — `CMakeLists.txt`, `conanfile.py`, `vcpkg.json`; malicious modifications can inject code at build time.
- **Never download and execute build scripts without verification** — verify GPG signatures or SHA-256 checksums of downloaded archives.
- **Review all `include` paths** — attacker-controlled include directories can shadow system headers with trojaned versions.
- **Sandbox the build environment** — use reproducible builds, hermetic build systems (Bazel, Nix), or container-based CI.
- **Run `cppcheck`, `Coverity`, or `Clang Static Analyzer`** as part of CI — detects memory safety bugs in dependencies and application code.
- **Subscribe to security advisories** for all major dependencies (OpenSSL, zlib, libcurl, libpng) via NVD, GitHub advisories, or vendor mailing lists.

```cmake
# ❌ INSECURE — FetchContent with mutable tag: supply chain risk
FetchContent_Declare(
    mylib
    GIT_REPOSITORY https://github.com/example/mylib.git
    GIT_TAG        main  # mutable: can be changed by upstream
)

# ✅ SECURE — FetchContent pinned to immutable SHA
FetchContent_Declare(
    mylib
    GIT_REPOSITORY https://github.com/example/mylib.git
    GIT_TAG        a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2  # immutable SHA
)

# ✅ SECURE — vcpkg with baseline pin
# vcpkg.json
{
  "dependencies": ["openssl", "zlib"],
  "builtin-baseline": "a1b2c3d4e5f6..."
}
```

---

## CVE Reference Table

| CVE | Severity | Component | Description | Fixed In |
|-----|----------|-----------|-------------|----------|
| CVE-2014-0160 | Critical (7.5) | OpenSSL (Heartbleed) | Heap buffer over-read in TLS heartbeat extension leaks up to 64 KB of memory | OpenSSL 1.0.1g |
| CVE-2021-3156 | High (7.8) | sudo (Baron Samedit) | Heap buffer overflow in `sudoedit` argument processing; local privilege escalation | sudo 1.9.5p2 |
| CVE-2022-3602 | Critical (9.8) | OpenSSL | Stack buffer overflow in X.509 certificate verification (punycode decoding) | OpenSSL 3.0.7 |
| CVE-2023-4911 | High (7.8) | glibc (Looney Tunables) | Buffer overflow in dynamic linker's `GLIBC_TUNABLES` processing; local privilege escalation | glibc 2.38-1 |
| CVE-2024-3094 | Critical (10.0) | XZ Utils (liblzma) | Backdoor injected via build system into liblzma; allowed SSH auth bypass on affected distros | xz 5.6.0–5.6.1 (reverted) |
| CVE-2024-6387 | Critical (8.1) | OpenSSH (regreSSHion) | Signal handler race condition (TOCTOU) in `sshd` allows unauthenticated remote code execution | OpenSSH 9.8p1 |
| CVE-2002-0083 | Critical (10.0) | OpenSSH | Signed integer overflow in channel code; remote privilege escalation | OpenSSH 3.1 |
| CVE-2024-2961 | High (8.8) | glibc iconv | Buffer overflow in `iconv` ISO-2022-CN-EXT converter; exploitable via PHP applications | glibc 2.39 |
| CVE-2021-4034 | High (7.8) | polkit pkexec | Path traversal + argument processing leading to local privilege escalation | polkit 0.120 |
| CVE-2023-38408 | Critical (9.8) | OpenSSH agent | Remote code execution via forwarded SSH agent and malicious SSH server | OpenSSH 9.3p2 |

---

## Security Checklist

### Buffer Safety
- [ ] `gets()` not used anywhere in the codebase (eliminated)
- [ ] `strcpy()` and `strcat()` not used with external data; replaced with `strlcpy()`/`strlcat()` or `snprintf`
- [ ] All `sprintf` calls replaced with `snprintf` with explicit size
- [ ] All `scanf("%s")` calls have width limit matching buffer size - 1
- [ ] C++ code uses `std::string`, `std::array`, `std::vector` over raw C arrays where possible

### Memory Management
- [ ] All pointers set to `NULL` after `free()` in C code
- [ ] C++ code uses `std::unique_ptr`/`std::shared_ptr` for heap allocations
- [ ] `malloc`/`free` and `new`/`delete` never mixed; array/scalar `new`/`delete` pairs match
- [ ] `realloc` failures handled with a temporary pointer to avoid leaking the original
- [ ] No dangling pointer dereferences (verified with AddressSanitizer in CI)

### Integer Safety
- [ ] Allocation sizes computed with overflow check (`__builtin_mul_overflow` or equivalent)
- [ ] No silent `size_t` → `int` truncation without range validation
- [ ] No signed integer arithmetic that can overflow in security-relevant paths
- [ ] `-ftrapv` enabled in debug/test builds for signed overflow detection

### Format Strings
- [ ] No `printf(user_data)` — all format strings are string literals
- [ ] `-Wformat -Wformat-security -Werror=format-security` enabled in compiler flags

### Uninitialized Memory
- [ ] All local variables initialized at declaration
- [ ] `calloc()` used where zero-initialization is required
- [ ] Struct padding zeroed with `= {0}` or `memset` before network/IPC copy
- [ ] MemorySanitizer (`-fsanitize=memory`) run in CI

### Null Pointer Safety
- [ ] Return values of `malloc`, `calloc`, `realloc`, `fopen`, `strdup` checked before use
- [ ] `realloc` uses a temporary pointer to prevent leak on failure
- [ ] `-Wnull-dereference` enabled

### Command Injection
- [ ] `system()` and `popen()` not used with any user-controlled input
- [ ] `execve()`/`execvp()` uses argument array form, not shell string
- [ ] Executable paths are absolute, not PATH-relative

### Race Conditions / TOCTOU
- [ ] `access()` + `open()` pattern not used; direct `open()` with error checking
- [ ] Temporary files created with `mkstemp()` — not `tmpnam()`/`tempnam()`
- [ ] Shared mutable state in multi-threaded code protected with `std::mutex`/`pthread_mutex_t`

### Type Safety (C++)
- [ ] No C-style casts in C++ code — named casts used throughout
- [ ] All `dynamic_cast<T*>` results checked for `nullptr`
- [ ] No `reinterpret_cast` between incompatible pointer types for aliasing
- [ ] Type punning uses `std::bit_cast` (C++20) or `memcpy`, not union or `reinterpret_cast`

### Cryptography
- [ ] `explicit_bzero()` or `memset_s()` used to zero sensitive buffers (not `memset()`)
- [ ] `rand()` / `random()` not used for security-sensitive values
- [ ] CSPRNG uses `getrandom()`, `arc4random_buf()`, or `randombytes_buf()` (libsodium)
- [ ] Token comparison uses constant-time function (`CRYPTO_memcmp`, `timingsafe_bcmp`)
- [ ] `mlock()` used for highly sensitive key material

### Compiler Hardening
- [ ] `-fstack-protector-strong` enabled in production builds
- [ ] `-fPIE -pie` enabled for executables (ASLR effective)
- [ ] `-Wl,-z,relro -Wl,-z,now` in linker flags (RELRO)
- [ ] `-D_FORTIFY_SOURCE=3 -O2` enabled
- [ ] AddressSanitizer + UBSan (`-fsanitize=address,undefined`) run in CI

### Supply Chain
- [ ] All dependencies pinned to exact versions with cryptographic checksums
- [ ] CMake FetchContent uses immutable SHA not mutable tags/branches
- [ ] Build system files (`CMakeLists.txt`, `conanfile.py`) reviewed in pull requests
- [ ] Security advisory subscriptions for OpenSSL, zlib, libcurl, and other major deps

---

## Tooling

| Tool | Purpose | Command / Notes |
|------|---------|-----------------|
| [AddressSanitizer (ASan)](https://github.com/google/sanitizers/wiki/AddressSanitizer) | Detects heap/stack/global buffer overflows, UAF, double free | `-fsanitize=address -fno-omit-frame-pointer` |
| [UBSan](https://clang.llvm.org/docs/UndefinedBehaviorSanitizer.html) | Detects undefined behavior: signed overflow, null deref, invalid shift | `-fsanitize=undefined` |
| [MemorySanitizer (MSan)](https://github.com/google/sanitizers/wiki/MemorySanitizer) | Detects reads from uninitialized memory | `-fsanitize=memory` (Clang only) |
| [Valgrind](https://valgrind.org/) | Dynamic memory analysis: leaks, UAF, invalid reads | `valgrind --leak-check=full --track-origins=yes ./app` |
| [cppcheck](http://cppcheck.sourceforge.net/) | Static analysis for C/C++: buffer overflows, null deref, uninitialized vars | `cppcheck --enable=all --error-exitcode=1 .` |
| [Clang Static Analyzer](https://clang-analyzer.llvm.org/) | Deep static analysis integrated with Clang | `scan-build make` |
| [CodeQL](https://codeql.github.com/) | GitHub semantic code analysis: injection, memory safety, crypto misuse | GitHub Actions integration |
| [Semgrep](https://semgrep.dev/) | Pattern-based SAST with C/C++ rules | `semgrep --config=p/c` |
| [Coverity](https://scan.coverity.com/) | Commercial-grade static analysis (free for open source) | Coverity Scan web service |
| [checksec](https://github.com/slimm609/checksec.sh) | Verifies binary hardening flags (canary, PIE, RELRO, NX) | `checksec --file=./binary` |
| [Flawfinder](https://dwheeler.com/flawfinder/) | Scans C/C++ for known-dangerous function calls | `flawfinder .` |
