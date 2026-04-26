# Checkpoint

> A Laravel security scanner that audits your application for common vulnerabilities — from known CVEs to hardcoded secrets — via a single Artisan command.

```
php artisan checkpoint:scan
```

---

## What it checks

| # | Check | Severity |
|---|-------|----------|
| 1 | **Composer CVE Audit** — runs `composer audit` and reports known advisories | `FAIL` |
| 2 | **NPM CVE Audit** — runs `npm audit` and flags critical/high vulnerabilities | `FAIL` / `WARN` |
| 3 | **Environment Configuration** — `APP_DEBUG`, `APP_KEY`, `APP_URL`, `SESSION_SECURE_COOKIE` | `WARN` |
| 4 | **`.gitignore` Sensitive Files** — ensures `.env`, `*.key`, `*.pem` are excluded; detects if `.env` is tracked by git | `FAIL` |
| 5 | **File Permissions** — flags world-readable `.env` or world-writable `storage/` | `WARN` |
| 6 | **Hardcoded Secrets** — scans PHP/JS files for API keys, Stripe tokens, AWS keys, GitHub PATs, PEM headers | `FAIL` |
| 7 | **SQL Injection Risks** — detects raw queries with variable interpolation (`DB::select("… $var")`, `->whereRaw(…)`) | `FAIL` |
| 8 | **Mass Assignment** — finds `$guarded = []`, `Model::unguard()`, or models with no fillable/guarded definition | `WARN` |
| 9 | **XSS** — flags unescaped `{!! $var !!}` in Blade views and raw `echo` of request input | `WARN` |
| 10 | **CSRF Protection** — detects forms with `POST`/`PUT`/`PATCH`/`DELETE` missing `@csrf`, and checks middleware is present | `FAIL` |
| 11 | **Open Redirect** — spots `redirect($request->…)` or `header('Location: ' . $var)` with unvalidated input | `WARN` |
| 12 | **Command Injection** — finds `exec`, `shell_exec`, `system`, `passthru`, `proc_open` called with unescaped variables | `FAIL` |
| 13 | **Insecure Deserialization** — detects `unserialize($userInput)` and the classic `unserialize(base64_decode(…))` exploit chain | `FAIL` |
| 14 | **Debug Functions in Production** — finds `var_dump`, `dd`, `dump`, `ray` left outside of test files | `WARN` |
| 15 | **Sensitive Data Exposure** — flags `display_errors = 1`, logging of passwords/tokens, and Telescope always-on config | `WARN` |

---

## Requirements

- PHP **8.2+**
- Laravel **10**, **11**, or **12**

---

## Installation

```bash
composer require --dev andreapollastri/checkpoint
```

The package auto-discovers itself via Laravel's package discovery — no manual registration needed.

---

## Usage

### Run all checks

```bash
php artisan checkpoint:scan
```

### Run only specific checks

```bash
php artisan checkpoint:scan --only="SQL Injection Risks,CSRF Protection"
```

### Skip specific checks

```bash
php artisan checkpoint:scan --skip="NPM CVE Audit,Debug Functions in Production Code"
```

### JSON output (for CI/CD pipelines)

```bash
php artisan checkpoint:scan --json
```

The command exits with code `1` if any check returns `FAIL`, making it suitable as a pipeline gate.

---

## Example output

```
  ██████╗██╗  ██╗███████╗ ██████╗██╗  ██╗██████╗  ██████╗ ██╗███╗  ██╗████████╗
 ██╔════╝██║  ██║██╔════╝██╔════╝██║ ██╔╝██╔══██╗██╔═══██╗██║████╗ ██║╚══██╔══╝
 ██║     ███████║█████╗  ██║     █████╔╝ ██████╔╝██║   ██║██║██╔██╗██║   ██║
 ██║     ██╔══██║██╔══╝  ██║     ██╔═██╗ ██╔═══╝ ██║   ██║██║██║╚████║   ██║
  ╚█████╗██║  ██║███████╗ ╚█████╗██║  ██╗██║      ╚█████╔╝██║██║ ╚███║   ██║
   ╚════╝╚═╝  ╚═╝╚══════╝  ╚════╝╚═╝  ╚═╝╚═╝       ╚════╝ ╚═╝╚═╝  ╚══╝   ╚═╝

  Laravel Security Scanner — andreapollastri/checkpoint
  Scanning: /var/www/my-app

  PASS  Composer CVE Audit
        No known CVEs in Composer dependencies.

  FAIL  Hardcoded Secrets
        3 potential hardcoded secret(s) found.
          ✗ app/Services/PaymentService.php:14 — 'api_key' => 'sk_live_abc123…'
          ✗ config/services.php:8 — $secret = 'supersecretvalue'
          ✗ app/Http/Controllers/WebhookController.php:31 — 'api_key' => 'ghp_…'

  WARN  Environment Configuration
        3 environment issue(s) found.
          ⚑ APP_DEBUG is true — full stack traces will be exposed to end users.
          ⚑ SESSION_SECURE_COOKIE is not enabled.
          ⚑ APP_URL is set to "http://localhost" — update it for production.

  ─────────────────────────────────────────────────────────
  Summary  12 passed  2 warning(s)  1 failed  (15 checks total)

  Scan result: FAIL — fix the issues above before deploying.
```

---

## Extending with custom checks

Create a class that extends `AbstractCheck` and return a `CheckResult`:

```php
use Checkpoint\Checks\AbstractCheck;
use Checkpoint\Checks\CheckResult;

class MyCustomCheck extends AbstractCheck
{
    public function name(): string
    {
        return 'My Custom Check';
    }

    public function run(): CheckResult
    {
        // your logic here
        return CheckResult::pass('Everything looks good.');
        // or: CheckResult::warn('Something to review.', ['detail one', 'detail two']);
        // or: CheckResult::fail('Critical issue found.', ['detail']);
    }
}
```

Then register it by building a `Scanner` manually instead of using the default:

```php
use Checkpoint\Scanner;

$scanner = Scanner::withDefaultChecks(base_path())
    ->add(new MyCustomCheck());
```

---

## CI/CD integration

### GitHub Actions

```yaml
- name: Security audit
  run: php artisan checkpoint:scan --json | tee checkpoint-report.json
```

### Exit codes

| Code | Meaning |
|------|---------|
| `0` | All checks passed (or warnings only) |
| `1` | At least one check returned `FAIL` |

---

## Architecture

```
src/
├── CheckpointServiceProvider.php   # auto-registers the command
├── Scanner.php                     # orchestrates all checks
├── Commands/
│   └── ScanCommand.php             # php artisan checkpoint:scan
└── Checks/
    ├── AbstractCheck.php           # base class
    ├── CheckResult.php             # pass / warn / fail value object
    ├── ComposerAuditCheck.php
    ├── NpmAuditCheck.php
    ├── EnvironmentCheck.php
    ├── GitIgnoreCheck.php
    ├── FilePermissionsCheck.php
    ├── HardcodedSecretsCheck.php
    ├── SqlInjectionCheck.php
    ├── MassAssignmentCheck.php
    ├── XssCheck.php
    ├── CsrfCheck.php
    ├── OpenRedirectCheck.php
    ├── CommandInjectionCheck.php
    ├── InsecureDeserializationCheck.php
    ├── DebugFunctionsCheck.php
    └── SensitiveExposureCheck.php
```

---

## License

MIT — [Andrea Pollastri](https://andreapollastri.net)
