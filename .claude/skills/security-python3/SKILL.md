---
name: Python 3 Security
description: >
  Detailed security rules for Python 3.x language and standard library.
  Activate when writing or reviewing Python code involving subprocess calls,
  file operations, XML/YAML parsing, cryptography, deserialization (pickle/marshal/yaml),
  eval/exec, regex, network/urllib, logging, zipfile/tarfile extraction, getattr with
  user input, or dependency management.
  Also activate when the user mentions CVE, bandit, injection, ZipSlip, or asks for
  a Python security review.
allowed-tools: Read
---

Read the `rules.md` file in this skill directory and apply those security rules to all code analysis and generation tasks.
