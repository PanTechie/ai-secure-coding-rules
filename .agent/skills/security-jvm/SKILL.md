---
name: Java & Kotlin (JVM) Security
description: >
  Activate when writing or reviewing Java or Kotlin code involving ObjectInputStream/XMLDecoder/
  XStream/Jackson deserialization, InitialContext.lookup/JNDI, SpelExpressionParser/SpEL,
  PreparedStatement/JDBC/JPA native queries, DocumentBuilderFactory/SAXParserFactory/XMLInputFactory
  (XXE), Runtime.exec/ProcessBuilder, AES/DES/MD5/SHA1/SecureRandom/java.util.Random, Paths.get/File
  (path traversal), DirContext/LDAP, URL/HttpURLConnection/HttpClient (SSRF/TLS), HttpSecurity/Spring
  Security configuration, @ModelAttribute/data binding, Pattern/regex on user input, Log4j/SLF4J
  logging, Maven/Gradle dependency management, kotlinx.serialization/@Polymorphic, Kotlin data class
  with sensitive fields, !! operator, coroutines with Spring Security, Kotlin object singletons,
  ScriptEngineManager/kotlin-scripting-jsr223, or kotlin-reflect.
  Also activate when the user mentions Log4Shell, Spring4Shell, Text4Shell, gadget chain, CVE,
  deserialization, XXE, SSRF, SpEL injection, or asks for a Java or Kotlin security review.
---

## Use this skill when

Activate when writing or reviewing Java or Kotlin code involving ObjectInputStream/XMLDecoder/XStream/Jackson deserialization, InitialContext.lookup/JNDI, SpelExpressionParser/SpEL, PreparedStatement/JDBC/JPA native queries, DocumentBuilderFactory/SAXParserFactory/XMLInputFactory (XXE), Runtime.exec/ProcessBuilder, AES/DES/MD5/SHA1/SecureRandom/java.util.Random, Paths.get/File (path traversal), DirContext/LDAP, URL/HttpURLConnection/HttpClient (SSRF/TLS), HttpSecurity/Spring Security configuration, @ModelAttribute/data binding, Pattern/regex on user input, Log4j/SLF4J logging, Maven/Gradle dependency management, kotlinx.serialization/@Polymorphic, Kotlin data class with sensitive fields, !! operator, coroutines with Spring Security, Kotlin object singletons, ScriptEngineManager/kotlin-scripting-jsr223, or kotlin-reflect. Also activate when the user mentions Log4Shell, Spring4Shell, Text4Shell, gadget chain, CVE, deserialization, XXE, SSRF, SpEL injection, or asks for a Java or Kotlin security review.

## Instructions

Read the `rules.md` file in this skill directory and apply those security rules to all code analysis and generation tasks.
