---
name: C# / .NET Security
description: >
  Activate when writing or reviewing C# code involving BinaryFormatter/SoapFormatter/TypeNameHandling,
  SqlCommand/FromSqlRaw/ExecuteSqlRaw, XmlDocument/XmlReader/DataSet.ReadXml, Process.Start,
  AES/DES/MD5/RNGCryptoServiceProvider, Path.Combine with user input, DirectorySearcher/LDAP,
  Regex on user input, HttpClient/ServerCertificateCustomValidationCallback, ILogger/Serilog/NLog,
  Assembly.Load/Activator.CreateInstance/Type.GetType, unsafe/stackalloc/fixed, ASP.NET Core
  middleware/CORS/CSRF/antiforgery/cookies/sessions, or NuGet package management.
  Also activate when the user mentions CVE, deserialization gadget chain, SQL injection,
  XXE, SSRF, ReDoS, open redirect, or asks for a C# or .NET security review.
---

## Use this skill when

Activate when writing or reviewing C# code involving BinaryFormatter/SoapFormatter/TypeNameHandling, SqlCommand/FromSqlRaw/ExecuteSqlRaw, XmlDocument/XmlReader/DataSet.ReadXml, Process.Start, AES/DES/MD5/RNGCryptoServiceProvider, Path.Combine with user input, DirectorySearcher/LDAP, Regex on user input, HttpClient/ServerCertificateCustomValidationCallback, ILogger/Serilog/NLog, Assembly.Load/Activator.CreateInstance/Type.GetType, unsafe/stackalloc/fixed, ASP.NET Core middleware/CORS/CSRF/antiforgery/cookies/sessions, or NuGet package management. Also activate when the user mentions CVE, deserialization gadget chain, SQL injection, XXE, SSRF, ReDoS, open redirect, or asks for a C# or .NET security review.

## Instructions

Read the `rules.md` file in this skill directory and apply those security rules to all code analysis and generation tasks.
