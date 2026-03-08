---
name: Next.js Security
description: >
  Activate when writing or reviewing Next.js code involving middleware/auth bypass/CVE-2025-29927,
  Server Actions authorization/CSRF/Zod validation, Route Handlers authentication/rate limiting,
  NEXT_PUBLIC_* environment variable leaks, next.config.js security headers/CSP/HSTS,
  next/image remotePatterns SSRF/open proxy, redirect()/permanentRedirect() open redirect,
  next-auth/Auth.js NEXTAUTH_SECRET/callbackUrl/callbacks misconfiguration,
  Server Component to Client Component data leakage/RSC payload, params/searchParams injection,
  fetch() SSRF in Server Components/CVE-2024-34351, getServerSideProps/__NEXT_DATA__ exposure,
  ISR cache poisoning/revalidatePath/revalidateTag/CVE-2024-46982, source map exposure,
  Middleware Edge Runtime JWT verification/jose/x-middleware-subrequest header.
  Also activate when the user mentions CVE-2025-29927, CVE-2024-46982, CVE-2024-34351,
  next-auth, Auth.js, Server Actions, App Router, middleware bypass, NEXT_PUBLIC secret,
  or asks for a Next.js security review.
allowed-tools: Read
---

Read the `rules.md` file in this skill directory and apply those security rules to all code analysis and generation tasks.
