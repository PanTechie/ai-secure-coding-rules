---
name: React Security
description: >
  Activate when writing or reviewing React code involving dangerouslySetInnerHTML/innerHTML/XSS,
  href/src/to props with user input/javascript: protocol, Object spread {...userObj} prototype pollution,
  REACT_APP_*/VITE_* environment variable leaks, react-router navigate/Link open redirect,
  useState/useReducer/Redux/Zustand/Recoil sensitive data in state, localStorage/sessionStorage JWT storage,
  style prop CSS injection, SSR JSON injection in <script> tags/serialize-javascript,
  useEffect access control race conditions, Server Components data exposure/SSRF (React 19),
  eval/new Function dynamic code execution, file upload client-side validation only,
  Content Security Policy configuration, npm audit/Snyk/DOMPurify/Zod supply chain and validation.
  Also activate when the user mentions CVE, dangerouslySetInnerHTML, XSS, prototype pollution,
  open redirect, token in localStorage, CSP, Trusted Types, React DevTools exposure,
  serialize-javascript, or asks for a React security review.
allowed-tools: Read
---

Read the `rules.md` file in this skill directory and apply those security rules to all code analysis and generation tasks.
