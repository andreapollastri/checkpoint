---
name: Project Checkpoint
description: andreapollastri/checkpoint is a Laravel package that runs security audits via `php artisan checkpoint:scan`
type: project
---

This repo is a Laravel composer package named `andreapollastri/checkpoint`.

**Why:** The user wanted a single Artisan command that audits a Laravel project for common security issues — CVEs, hardcoded secrets, SQL injection, XSS, CSRF, mass assignment, command injection, insecure deserialization, open redirects, debug code left in production, and environment misconfiguration.

**How to apply:** When suggesting improvements, keep the architecture: each check is a class extending `AbstractCheck`, returning a `CheckResult` (pass/warn/fail). The `Scanner` orchestrates them. The command is `php artisan checkpoint:scan`. New checks go in `src/Checks/`.
