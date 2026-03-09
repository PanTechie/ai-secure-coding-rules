---
name: Express.js Security
description: >
  Activate when writing or reviewing Express.js code involving middleware order/auth bypass,
  SQL injection (pg/mysql2/Sequelize/Prisma), NoSQL injection (MongoDB/$where/$ne),
  command injection (child_process exec/spawn), path traversal (sendFile/fs), CORS misconfiguration,
  Helmet.js security headers, express-rate-limit (CVE-2024-29415), express-session hardening,
  JWT/jsonwebtoken (CVE-2022-23529/alg:none), csrf-csrf CSRF protection, template engine XSS
  (EJS <%- vs <%=, Handlebars triple braces, Pug !=), mass assignment via req.body,
  multer file upload validation, centralized error handler stack trace exposure.
  Also activate when the user mentions CVE-2022-24999, CVE-2024-29415, CVE-2022-23529,
  body-parser, qs prototype pollution, jsonwebtoken, multer, Helmet, express-rate-limit,
  express-session, csurf, csrf-csrf, or asks for an Express.js security review.
allowed-tools: Read
---

Read the `rules.md` file in this skill directory and apply those security rules to all code analysis and generation tasks.
