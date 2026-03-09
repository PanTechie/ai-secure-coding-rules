---
name: Vue.js Security
description: >
  Activate when writing or reviewing Vue.js or Nuxt.js code involving v-html XSS/DOMPurify,
  :href/:src URL protocol injection (javascript:), Vue.compile() template injection/SSTI,
  Pinia/Vuex sensitive state exposure, VITE_*/VUE_APP_* environment variable leaks,
  Vue Router open redirect, Route Guard client-side-only bypass, Nuxt useState/payload hydration XSS,
  Nuxt server route authentication, useFetch/$fetch SSRF, prototype pollution via reactive merging,
  ReDoS in custom validators, :style CSS injection, CSP unsafe-eval with runtime compiler,
  nuxt-security module, vite.config.ts hardening, production build (devtools/sourceMap).
  Also activate when the user mentions CVE-2025-30208, CVE-2023-3224, CVE-2024-6783,
  v-html, DomSanitizer, Nuxt, Pinia, vue-router, VITE_, or asks for a Vue security review.
---

## Use this skill when

Activate when writing or reviewing Vue.js or Nuxt.js code involving v-html XSS/DOMPurify,
:href/:src URL protocol injection (javascript:), Vue.compile() template injection/SSTI,
Pinia/Vuex sensitive state exposure, VITE_*/VUE_APP_* environment variable leaks,
Vue Router open redirect, Route Guard client-side-only bypass, Nuxt useState/payload hydration XSS,
Nuxt server route authentication, useFetch/$fetch SSRF, prototype pollution via reactive merging,
ReDoS in custom validators, :style CSS injection, CSP unsafe-eval with runtime compiler,
nuxt-security module, vite.config.ts hardening, production build (devtools/sourceMap).
Also activate when the user mentions CVE-2025-30208, CVE-2023-3224, CVE-2024-6783,
v-html, DomSanitizer, Nuxt, Pinia, vue-router, VITE_, or asks for a Vue security review.

## Instructions

Read the `rules.md` file in this skill directory and apply those security rules to all code analysis and generation tasks.
