# Checkpoint

> A Laravel security scanner that audits your application for common vulnerabilities — from known CVEs to hardcoded secrets — via a single Artisan command.

```
php artisan checkpoint:scan
```

---

## What it checks

| #   | Check                                                                                                                          | Severity        |
| --- | ------------------------------------------------------------------------------------------------------------------------------ | --------------- |
| 1   | **Composer CVE Audit** — runs `composer audit` and reports known advisories                                                    | `FAIL`          |
| 2   | **NPM CVE Audit** — runs `npm audit` and flags critical/high vulnerabilities                                                   | `FAIL` / `WARN` |
| 3   | **Environment Configuration** — `APP_DEBUG`, `APP_KEY`, `APP_URL`, `SESSION_SECURE_COOKIE`                                     | `WARN`          |
| 4   | **`.gitignore` Sensitive Files** — ensures `.env`, `*.key`, `*.pem` are excluded; detects if `.env` is tracked by git          | `FAIL`          |
| 5   | **File Permissions** — flags world-readable `.env` or world-writable `storage/`                                                | `WARN`          |
| 6   | **Hardcoded Secrets** — scans PHP/JS files for API keys, Stripe tokens, AWS keys, GitHub PATs, PEM headers                     | `FAIL`          |
| 7   | **SQL Injection Risks** — detects raw queries with variable interpolation (`DB::select("… $var")`, `->whereRaw(…)`)            | `FAIL`          |
| 8   | **Mass Assignment** — finds `$guarded = []`, `Model::unguard()`, or models with no fillable/guarded definition                 | `WARN`          |
| 9   | **XSS** — flags unescaped `{!! $var !!}` in Blade views and raw `echo` of request input                                        | `WARN`          |
| 10  | **CSRF Protection** — detects forms with `POST`/`PUT`/`PATCH`/`DELETE` missing `@csrf`, and checks middleware is present       | `FAIL`          |
| 11  | **Open Redirect** — spots `redirect($request->…)` or `header('Location: ' . $var)` with unvalidated input                      | `WARN`          |
| 12  | **Command Injection** — finds `exec`, `shell_exec`, `system`, `passthru`, `proc_open` called with unescaped variables          | `FAIL`          |
| 13  | **Insecure Deserialization** — detects `unserialize($userInput)` and the classic `unserialize(base64_decode(…))` exploit chain | `FAIL`          |
| 14  | **Debug Functions in Production** — finds `var_dump`, `dd`, `dump`, `ray` left outside of test files                           | `WARN`          |
| 15  | **Sensitive Data Exposure** — flags `display_errors = 1`, logging of passwords/tokens, and Telescope always-on config          | `WARN`          |
| 16  | **SSRF Risks** — detects `Http::get($request->…)`, Guzzle/cURL/`file_get_contents` called with user-controlled URLs            | `FAIL`          |
| 17  | **TLS Certificate Verification** — flags `withoutVerifying()`, `'verify' => false`, `CURLOPT_SSL_VERIFYPEER => false`          | `FAIL`          |
| 18  | **CORS Configuration** — flags `allowed_origins => ['*']` combined with `supports_credentials => true` and other loose configs | `FAIL` / `WARN` |
| 19  | **Package Freshness (Supply Chain)** — fails the scan if any Composer package was released within the last N days (default 3); whitelist via config | `FAIL`          |
| 20  | **Supply Chain Tooling** — when `package.json` is present, warns if no npm install-time guard (Safe-Chain, Socket CLI) is on PATH            | `WARN`          |

---

## Requirements

- **PHP** `^8.1` (see [Framework support](#framework-support) for how your Laravel version may raise the floor)
- **Laravel** `8`–`13` (same major as `illuminate/*` 8.x–13.x used by your app)

---

## Installation

```bash
composer require --dev andreapollastri/checkpoint
```

The package auto-discovers itself via Laravel's package discovery — no manual registration needed.

---

## Recommended companion tools

Checkpoint is a static scanner — it inspects your codebase but doesn't intercept package installs. To harden the npm install path against the next event-stream/ua-parser-js/chalk-style supply-chain attack, pair Checkpoint with a runtime guard:

### Safe-Chain (recommended)

[Safe-Chain](https://www.npmjs.com/package/@aikidosec/safe-chain) by Aikido is a free shell shim that blocks known-malicious npm packages **before** their install scripts run. Install it once, globally:

```bash
npm install -g @aikidosec/safe-chain
safe-chain setup
```

Checkpoint's **Supply Chain Tooling** check verifies whether Safe-Chain (or an equivalent like Socket CLI) is on your `PATH` and emits a `WARN` if no protection is present.

> Why Checkpoint doesn't install it for you: Safe-Chain works as a global shell shim, not a project dependency. A `composer require` should never invoke another ecosystem's package manager (and can't reliably do so on hosts without Node). Installing it explicitly keeps the install path auditable.

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

## Configuration

Checkpoint works out of the box with sensible defaults. Publish the config file when you need to toggle individual checks or tune the freshness gate:

```bash
php artisan vendor:publish --tag=checkpoint-config
```

This creates `config/checkpoint.php` with two sections:

### Enabling / disabling checks

Every default check is listed and enabled. Set any entry to `false` to exclude it from the scan:

```php
'checks' => [
    Checks\ComposerAuditCheck::class      => true,
    Checks\NpmAuditCheck::class           => false, // skip npm audit on a PHP-only project
    Checks\EnvironmentCheck::class        => true,
    // …
    Checks\PackageFreshnessCheck::class   => true,
    Checks\SupplyChainToolingCheck::class => true,
],
```

> Checks not listed in the map fall back to **enabled**. When you upgrade Checkpoint and new checks are added, you keep the protection without re-publishing the config — re-publish only when you want to see the full updated list.

### Package Freshness tuning

```php
'package_freshness' => [
    'minimum_age_days' => 3,
    'whitelist' => [
        // 'laravel/framework',
        // 'symfony/console',
    ],
],
```

- `minimum_age_days` — packages released more recently than this fail the scan. Default `3`.
- `whitelist` — fully-qualified package names (`vendor/package`) exempt from the freshness check. Use sparingly and ideally with an inline comment explaining why each entry is allowed.

### Suppressing individual findings

Every `WARN` or `FAIL` finding is shown with a stable 12-character hash:

```
FAIL  Hardcoded Secrets
      3 potential hardcoded secret(s) found.
        ✗ app/Services/PaymentService.php:14 — 'api_key' => 'sk_live_…' [a1b2c3d4e5f6]
        ✗ config/services.php:8 — $secret = 'super…'                    [9f8e7d6c5b4a]
```

To silence one — false positive, accepted legacy code, internal test fixture — copy the bracketed hash into `config/checkpoint.php`:

```php
'suppressed' => [
    'a1b2c3d4e5f6',
    '9f8e7d6c5b4a',
],
```

On the next run those findings are filtered out. If every finding of a given check ends up suppressed, the check is downgraded to `PASS` with an explicit `"All N finding(s) suppressed via config."` message — so the suppression is visible in the output, not silently ignored.

The hash is content-stable: refactors that only shift line numbers within the same file will **not** invalidate the suppression. The hash *does* change if you alter the file path or the finding content itself, which is the intended safety net.

> The `--only` / `--skip` CLI flags still work and override the config for the current run, which is handy for ad-hoc scans without editing the config.

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

Checkpoint can scaffold a ready-to-use pipeline for either provider in one command.

### GitHub Actions

```bash
php artisan checkpoint:github
```

Creates `.github/workflows/checkpoint.yml` — triggers on push to `main`/`master` and on every pull request. Uses `actions/checkout@v4`, `shivammathur/setup-php@v2` (PHP 8.2), Composer cache, and runs `php artisan checkpoint:scan`. Pass `--force` to overwrite an existing file.

### GitLab CI

```bash
php artisan checkpoint:gitlab
```

Creates `.gitlab-ci.yml` — runs on merge requests and default-branch pushes using the `composer:2` image with a Composer cache. If you already have a `.gitlab-ci.yml`, the command refuses to overwrite and prints the snippet to stdout so you can paste it into your existing pipeline. Use `--force` to overwrite.

### Custom usage

If you prefer to wire Checkpoint into a pipeline you already maintain, just call:

```yaml
- name: Security audit
  run: php artisan checkpoint:scan --json | tee checkpoint-report.json
```

### Composer hooks

Run Checkpoint automatically after every `composer install` / `composer update`:

```bash
php artisan checkpoint:install-hooks
```

This appends `@php artisan checkpoint:scan` to `scripts.post-update-cmd` and `scripts.post-install-cmd` in your `composer.json`. The command:

- Confirms interactively before touching `composer.json` (skip the prompt with `--no-interaction` for CI).
- Is idempotent: re-running on an already-installed setup is a no-op.
- Preserves any existing hooks (append-only); does **not** overwrite scripts owned by other tools.
- Supports `--remove` to cleanly uninstall and `--force` to replace stale Checkpoint entries.

> **Why only `post-*`, not `pre-*`?** Composer's `pre-update-cmd` fires *before* dependencies are resolved, so the scanner would only see the codebase pre-update — useless against a malicious package that's about to be installed. And on a fresh clone there is no `vendor/`, so `php artisan` does not exist yet and `pre-install-cmd` would crash. Real-time interception of malicious installs is the job of [Safe-Chain](#recommended-companion-tools).

### Exit codes

| Code | Meaning                              |
| ---- | ------------------------------------ |
| `0`  | All checks passed (or warnings only) |
| `1`  | At least one check returned `FAIL`   |

---

## Architecture

```
src/
├── CheckpointServiceProvider.php   # auto-registers the command
├── Scanner.php                     # orchestrates all checks
├── Commands/
│   ├── ScanCommand.php             # php artisan checkpoint:scan
│   ├── GithubPipelineCommand.php   # php artisan checkpoint:github
│   ├── GitlabPipelineCommand.php   # php artisan checkpoint:gitlab
│   └── InstallHooksCommand.php     # php artisan checkpoint:install-hooks
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
    ├── SensitiveExposureCheck.php
    ├── SsrfCheck.php
    ├── TlsVerificationCheck.php
    ├── CorsConfigCheck.php
    ├── PackageFreshnessCheck.php
    └── SupplyChainToolingCheck.php
```

---

## License

MIT — [Andrea Pollastri](https://andreapollastri.net)
