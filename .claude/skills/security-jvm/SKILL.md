---
name: Java & Kotlin (JVM) Security
description: >
  Detailed security rules for Java 11+ and Kotlin 1.9+ on the JVM, including Spring Boot.
  Activate when writing or reviewing Java or Kotlin code involving ObjectInputStream/XMLDecoder/
  XStream/Jackson deserialization, InitialContext.lookup/JNDI, SpelExpressionParser/SpEL,
  PreparedStatement/JDBC/JPA native queries, DocumentBuilderFactory/SAXParserFactory/XMLInputFactory
  (XXE), Runtime.exec/ProcessBuilder, AES/DES/MD5/SHA1/SecureRandom/java.util.Random, Paths.get/File
  (path traversal), DirContext/LDAP, URL/HttpURLConnection/HttpClient (SSRF/TLS), HttpSecurity/Spring
  Security configuration, @ModelAttribute/data binding, Pattern/regex on user input, Log4j/SLF4J
  logging, Maven/Gradle dependency management, kotlinx.serialization/@Polymorphic, Kotlin data class
  with sensitive fields, !! operator, coroutines with Spring Security, or Kotlin object singletons.
  Also activate when the user mentions Log4Shell, Spring4Shell, Text4Shell, gadget chain, CVE,
  deserialization, XXE, SSRF, SpEL injection, or asks for a Java or Kotlin security review.
allowed-tools: Read
---

Read the `rules.md` file in this skill directory and apply those security rules to all code analysis and generation tasks.
