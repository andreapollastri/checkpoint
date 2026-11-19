# Checkpoint

> A Laravel security scanner that audits your application for common vulnerabilities — from known CVEs to hardcoded secrets — via a single Artisan command.

```
php artisan checkpoint:scan
```

---

## What it checks

| #   | Check                                                                                                                                                                                                       | Severity        |
| --- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | --------------- |
| 1   | **Composer CVE Audit** — runs `composer audit` against `composer.lock` and reports known advisories; warns (never passes) if Composer cannot run                                                            | `FAIL` / `WARN` |
| 2   | **NPM CVE Audit** — runs `npm audit` (or `bun audit` for Bun projects with `bun.lock` / `bun.lockb`) and flags critical/high vulnerabilities; warns if the tool cannot run or the lockfile is unsupported (yarn/pnpm) | `FAIL` / `WARN` |
| 3   | **Environment Configuration** — `APP_DEBUG`, `APP_KEY`, `APP_URL`, `SESSION_SECURE_COOKIE`                                                                                                                  | `WARN`          |
| 4   | **`.gitignore` Sensitive Files** — ensures `.env`, `*.key`, `*.pem`, `auth.json` are excluded; detects if `.env` or `auth.json` is tracked by git                                                           | `FAIL`          |
| 5   | **File Permissions** — flags world-readable `.env` or world-writable `storage/`                                                                                                                             | `WARN`          |
| 6   | **Hardcoded Secrets** — scans PHP/JS files for API keys, Stripe tokens, AWS keys, GitHub PATs, PEM headers                                                                                                  | `FAIL`          |
| 7   | **SQL Injection Risks** — detects raw queries with variable interpolation (`DB::select("… $var")`, `->whereRaw(…)`)                                                                                         | `FAIL`          |
| 8   | **Mass Assignment Vulnerabilities** — finds `$guarded = []` or `Model::unguard()`                                                                                                                           | `WARN`          |
| 9   | **XSS (Cross-Site Scripting) Risks** — flags unescaped `{!! $var !!}` in Blade views and raw `echo` of request input                                                                                        | `WARN`          |
| 10  | **CSRF Protection** — detects forms with `POST`/`PUT`/`PATCH`/`DELETE` missing `@csrf`, and checks middleware is present                                                                                    | `FAIL`          |
| 11  | **Open Redirect Risks** — spots `redirect($request->…)` or `header('Location: ' . $var)` with unvalidated input                                                                                             | `WARN`          |
| 12  | **Command Injection Risks** — finds `exec`, `shell_exec`, `system`, `passthru`, `proc_open` called with unescaped variables                                                                                 | `FAIL`          |
| 13  | **Insecure Deserialization** — detects `unserialize($userInput)` and the classic `unserialize(base64_decode(…))` exploit chain                                                                              | `FAIL`          |
| 14  | **Debug Functions in Production Code** — finds `var_dump`, `dd`, `dump`, `ray` left outside of test files                                                                                                   | `WARN`          |
| 15  | **Sensitive Data Exposure** — flags `display_errors = 1`, logging of passwords/tokens, and Telescope always-on config                                                                                       | `WARN`          |
| 16  | **SSRF Risks** — detects `Http::get($request->…)`, Guzzle/cURL/`file_get_contents` called with user-controlled URLs                                                                                         | `FAIL`          |
| 17  | **TLS Certificate Verification** — flags `withoutVerifying()`, `'verify' => false`, `CURLOPT_SSL_VERIFYPEER => false`                                                                                       | `FAIL`          |
| 18  | **CORS Configuration** — flags `allowed_origins => ['*']` combined with `supports_credentials => true` and other loose configs                                                                              | `FAIL` / `WARN` |
| 19  | **Package Freshness (Supply Chain)** — fails the scan if any Composer package was released within the last N days (default 3); whitelist via config                                                         | `FAIL`          |
| 20  | **Supply Chain Tooling** — when `package.json` is present, warns if no npm install-time guard (Safe-Chain, Socket CLI) is on PATH                                                                           | `WARN`          |
| 21  | **Path Traversal Risks** — detects `Storage::get($request->…)`, `file_get_contents`/`include`/`require` with user-controlled paths                                                                          | `FAIL`          |
| 22  | **Weak Cryptography** — flags `mcrypt_*`, ECB mode, DES/3DES/RC4, and `md5`/`sha1` used near password/token/HMAC keywords                                                                                   | `FAIL` / `WARN` |
| 23  | **Insecure RNG** — detects `rand`/`mt_rand`/`uniqid` used in security contexts (tokens, CSRF, password reset, OTP)                                                                                          | `FAIL`          |
| 24  | **Session & Cookie Security** — audits `config/session.php` for `http_only=false`, `same_site=null/none`, `secure=false`, `encrypt=false`                                                                   | `WARN`          |
| 25  | **EOL Versions** — flags Composer-locked Laravel and the running PHP past their security cutoff (FAIL) or within 12 months of it (WARN)                                                                     | `FAIL` / `WARN` |
| 26  | **Suspicious Vendor Autoload** — flags packages under `vendor/` that register PHP via `autoload.files` outside a baked-in whitelist (the mechanism abused by the May 2026 Laravel-Lang supply-chain attack) | `WARN`          |
| 27  | **Outdated Composer Packages** — runs `composer outdated --direct` and lists direct dependencies behind their latest release (minor/patch vs major)                                                         | `WARN`          |
| 28  | **Abandoned Composer Packages** — flags packages marked abandoned in `composer.lock`, with the suggested replacement                                                                                        | `WARN`          |
| 29  | **Composer Configuration** — flags `secure-http: false`, `disable-tls`, `http://` repositories, credentials in `composer.json`, `allow-plugins: true`, unstable `minimum-stability`, and silenced audits    | `FAIL` / `WARN` |
| 30  | **XML External Entity (XXE) Risks** — detects `LIBXML_NOENT`, `LIBXML_DTDLOAD`, `libxml_disable_entity_loader(false)` and other opt-ins to entity/DTD loading                                               | `FAIL`          |
| 31  | **PHP CVE Audit** — matches the running PHP version against a bundled database of PHP security releases (CVE / GHSA per release) plus the live php.net release feed; flags end-of-life branches and pre-release builds | `FAIL` / `WARN` |
| 32  | **PHP Configuration (php.ini)** — audits the CLI runtime, `public/.user.ini` and the web-SAPI `php.ini` for `allow_url_include`, `display_errors`, `expose_php`, `auto_prepend_file`, `cgi.force_redirect`, active Xdebug and more | `FAIL` / `WARN` |
| 33  | **Public Directory Exposure** — finds `.env`, `.git`, `phpinfo()`, Adminer / phpMyAdmin, SQL dumps and stray PHP files under `public/`, executable files in `storage/app/public`, and a web-served project root | `FAIL` / `WARN` |

---

## Requirements

- **PHP** `8.1` – `8.6`. `^8.1` is the package floor; newer Laravel versions may require a higher PHP, so your effective minimum is whatever your Laravel major demands.
- **Laravel** `8`–`13` (same major as `illuminate/*` 8.x–13.x used by your app)

---

## Installation

```bash
composer require --dev andreapollastri/checkpoint
```

The package auto-discovers itself via Laravel's package discovery — no manual registration needed.

---

## Recommended companion tools

Checkpoint is a static scanner — it inspects your codebase but doesn't intercept package installs. To harden the npm install path against the next event-stream/ua-parser-js/chalk-style supply-chain attack, pair Checkpoint with **defense in depth**: run installs inside containers and add a runtime guard on the host when you must install locally.

### Docker (recommended)

Run `composer install`, `npm install`, and `php artisan checkpoint:scan` **inside a container**, not directly on your laptop or server shell. Supply-chain malware often executes during a package's post-install script — if that runs on your host, it has access to your SSH keys, browser cookies, and filesystem. A disposable dev container limits blast radius to an isolated filesystem that you can throw away.

Typical workflow:

```bash
docker compose up -d
docker compose exec app composer install
docker compose exec app npm install
docker compose exec app php artisan checkpoint:scan
```

Use whatever Docker setup fits your project — Docker Compose, a devcontainer, or a CI image such as `composer:2` with Node in the same job. The goal is the same: **never let untrusted install scripts run on bare metal**; treat the host as a control plane only.

> Checkpoint's CI scaffolds ([GitHub Actions](#github-actions), [GitLab CI](#gitlab-ci)) already run the scan inside ephemeral containers. Mirror that pattern locally.

### Safe-Chain (recommended)

[Safe-Chain](https://www.npmjs.com/package/@aikidosec/safe-chain) by Aikido is a free shell shim that blocks known-malicious npm packages **before** their install scripts run. Install it once, globally:

```bash
npm install -g @aikidosec/safe-chain
safe-chain setup
```

When you **do** run npm on the host (CI runners, one-off scripts), Safe-Chain blocks known-malicious packages **before** their install scripts run. Checkpoint's **Supply Chain Tooling** check verifies whether Safe-Chain (or an equivalent like Socket CLI) is on your `PATH` and emits a `WARN` if no protection is present.

> Why Checkpoint doesn't install it for you: Safe-Chain works as a global shell shim, not a project dependency. A `composer require` should never invoke another ecosystem's package manager (and can't reliably do so on hosts without Node). Installing it explicitly keeps the install path auditable. Prefer Docker for day-to-day installs; keep Safe-Chain as a safety net where containers aren't practical.

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

### Fail the pipeline on warnings

By default, warnings exit with code `0`. For stricter gates:

```bash
php artisan checkpoint:scan --fail-on-warn
```

The command exits with code `1` if any check returns `FAIL` (or `WARN` when `--fail-on-warn` is set), making it suitable as a pipeline gate.

---

## Configuration

Checkpoint works out of the box with sensible defaults. Publish the config file when you need to toggle individual checks or tune the freshness gate:

```bash
php artisan vendor:publish --tag=checkpoint-config
```

This creates `config/checkpoint.php` with sections for toggles, custom checks, freshness, outdated packages, PHP CVE / `php.ini` auditing, suppressions, and path exclusions.

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

### Custom checks

```php
'extra_checks' => [
    \App\Security\MyCustomCheck::class,
],
```

Listed classes are appended after the built-ins when you run `php artisan checkpoint:scan`. See [Extending with custom checks](#extending-with-custom-checks).

### Package Freshness tuning

```php
'package_freshness' => [
    'minimum_age_days' => 3,
    'whitelist' => [
        'andreapollastri/checkpoint', // bundled — see note below
        // 'laravel/framework',
        // 'symfony/console',
    ],
],
```

- `minimum_age_days` — packages released more recently than this fail the scan. Default `3`. **Set to `0` to bypass the freshness gate entirely** without removing the check from the scanner.
- `whitelist` — fully-qualified package names (`vendor/package`) exempt from the freshness check. Use sparingly and ideally with an inline comment explaining why each entry is allowed.

> Checkpoint ships with `andreapollastri/checkpoint` already whitelisted by default — a fresh release of the scanner itself should never block its own user's deploy. Remove the entry if you want to gate even Checkpoint upgrades through the freshness window.

### Outdated packages tuning

```php
'outdated_packages' => [
    'include_dev' => false,
    'ignore' => [
        // 'vendor/package',
        // 'acme/*',
    ],
],
```

- `include_dev` — also report outdated `require-dev` dependencies. Default `false` (production dependencies only).
- `ignore` — packages you deliberately pin. Exact names or `vendor/*` wildcards.

The check runs `composer outdated --locked --direct`, so it needs network access to Packagist but not a populated `vendor/`.

### PHP CVE Audit

```php
'php_cve' => [
    'live_lookup' => true,
],
```

The check compares the PHP version running the scan with two sources:

- a **bundled database** (`resources/php-advisories.php`) of every PHP security release since 8.1 and the CVE / GHSA advisories each one fixes, generated from the official php.net changelog — one finding per advisory, e.g. `CVE-2024-4577 — CGI: Bypass of CVE-2012-1823, Argument Injection in PHP-CGI (fixed in PHP 8.3.8)`;
- the **php.net release feed** (one HTTPS request to `www.php.net/releases`), so a security release published after your installed Checkpoint version is still caught.

It also fails for end-of-life branches (advisories fixed elsewhere are never backported) and warns for pre-release builds (alpha / beta / RC).

- `live_lookup` — set to `false` for air-gapped CI. The check then relies on the bundled database only and says so in its message. When the lookup is enabled but php.net is unreachable, the check **warns** rather than reporting a PASS it cannot back up.
- **Ubuntu builds** (`8.3.6-0ubuntu0.24.04.x`) are reported as `WARN` instead of `FAIL`: Ubuntu backports security fixes without changing the upstream version, so the version number alone does not prove the build is vulnerable. Other distributions that backport silently (e.g. RHEL AppStream) cannot be told apart from upstream builds — suppress the advisories your vendor has patched.
- Advisories that only affect Windows are skipped on other operating systems.
- Each advisory is suppressed by its id, so the hash stays the same on every machine and PHP version.

### PHP configuration (`php.ini`)

```php
'php_ini' => [
    'files' => [
        // '/usr/local/etc/php-fpm/php.ini',
        // '/etc/php/8.6/fpm/conf.d',
    ],
],
```

`php artisan` runs on the CLI, whose configuration is not always the one your web server uses. The check therefore audits every configuration it can reach:

- the **CLI runtime** — the values from `php.ini`, not the ones Laravel overrides while booting;
- **`public/.user.ini`**, when present;
- on **Debian / Ubuntu**, the `php.ini` and `conf.d/*.ini` of the web SAPIs installed next to the CLI one (`/etc/php/X.Y/{fpm,apache2,cgi}`);
- any file or `conf.d` directory listed in `files` (absolute, or relative to the project root). A listed file that cannot be read is reported — never silently skipped.

Setups where CLI and FPM share one `php.ini` (the official Docker images, Homebrew) are already covered by the runtime audit. Files are judged only on the directives they set explicitly, and per-pool PHP-FPM overrides (`php_admin_value[...]`) are not read.

| Directive | Flagged when | Severity |
| --- | --- | --- |
| `allow_url_include` | `On` — remote file inclusion; also the switch flipped by PHP-CGI argument-injection exploits (CVE-2012-1823, CVE-2024-4577) | `FAIL` |
| `display_errors`, `display_startup_errors` | `On` — errors printed to visitors | `WARN` |
| `expose_php` | `On` — `X-Powered-By` advertises the exact PHP version | `WARN` |
| `zend.exception_ignore_args` | `Off` — stack traces carry function arguments (passwords, tokens) | `WARN` |
| `error_include_args` (PHP 8.6+) | `On` — error messages carry function arguments | `WARN` |
| `auto_prepend_file`, `auto_append_file` | set — runs on every request; a common webshell persistence trick (Herd's dump loader is ignored) | `WARN` |
| `cgi.force_redirect` | `0` — php-cgi reachable directly (CVE-2012-1823, CVE-2024-8927) | `WARN` |
| `xdebug.mode`, `xdebug.discover_client_host` | Xdebug active / connecting back to any client | `WARN` |

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

The hash is content-stable: refactors that only shift line numbers within the same file will **not** invalidate the suppression. The hash _does_ change if you alter the file path or the finding content itself, which is the intended safety net.

Package Freshness and Outdated Composer Packages findings are an exception: their hash is based on **package name + installed version only**, so a suppression survives the displayed age (`released 5h ago`) changing every hour, or a newer upstream release appearing. It expires as soon as you install a different version.

Checks may also supply their own per-detail hashes via the optional fourth argument to `CheckResult::fail()` / `warn()` / `pass()` — a `detail => hash` map. When present, that hash is used for display, JSON output, and suppression instead of hashing the detail text.

> The `--only` / `--skip` CLI flags still work and override the config for the current run, which is handy for ad-hoc scans without editing the config.

### Excluding folders from file scans

File-based checks (Hardcoded Secrets, SQL Injection, XSS, and others) skip built-in paths such as `vendor/`, `node_modules/`, and `storage/`. Add your own paths when you have mounted data directories or other folders that are not part of your application source:

```php
'exclude_paths' => [
    'storage/app/mounted-data',
    'data/external',
],
```

Paths are relative to the project root. Leading and trailing slashes are optional. Unreadable directories are skipped automatically so permission errors on mounted volumes do not abort the scan.

---

## Example output

```
  ┌─┐┬ ┬┌─┐┌─┐┬┌─┌─┐┌─┐┬┌┐┌┌┬┐
  │  ├─┤├┤ │  ├┴┐├─┘│ │││││ │ 
  └─┘┴ ┴└─┘└─┘┴ ┴┴  └─┘┴┘└┘ ┴ 

  Laravel Security Scanner — andreapollastri/checkpoint
  Scanning: /var/www/my-app

  33/33 [============================] 100% Public Directory Exposure

  PASS  Composer CVE Audit
        No known CVEs in Composer dependencies.

  FAIL  Hardcoded Secrets
        3 potential hardcoded secret(s) found.
          ✗ app/Services/PaymentService.php:14 — 'api_key' => 'sk_live_abc123…' [a1b2c3d4e5f6]
          ✗ config/services.php:8 — $secret = 'supersecretvalue'             [9f8e7d6c5b4a]
          ✗ app/Http/Controllers/WebhookController.php:31 — 'api_key' => 'ghp_…' [3e2d1c0b9a8f]

  FAIL  Path Traversal Risks
        1 potential path traversal risk(s) found.
          ✗ app/Http/Controllers/DownloadController.php:24 — Storage::get($request->path) [7b6a5f4e3d2c]

  WARN  Environment Configuration
        3 environment issue(s) found.
          ⚑ APP_DEBUG is true — full stack traces will be exposed to end users. [5c4b3a2d1e0f]
          ⚑ SESSION_SECURE_COOKIE is not enabled.                               [1a2b3c4d5e6f]
          ⚑ APP_URL is set to "http://localhost" — update it for production.    [6e5d4c3b2a1f]

  ─────────────────────────────────────────────────────────
  Summary  27 passed  4 warning(s)  2 failed  (33 checks total)

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

Register it in `config/checkpoint.php` so `php artisan checkpoint:scan` picks it up:

```php
'extra_checks' => [
    \App\Security\MyCustomCheck::class,
],
```

Constructors may take no arguments, or a single `$basePath` string (same convention as built-in checks). You can still disable an extra check via the `checks` map.

Alternatively, build a `Scanner` manually:

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

Creates `.github/workflows/checkpoint.yml` — triggers on push to `main`/`master` and on every pull request. Uses `actions/checkout@v4`, `shivammathur/setup-php@v2` (the PHP version running the command, or `--php=8.6` to pick one), Composer cache, optional Node/`npm ci` when `package-lock.json` is present, Bun when `bun.lock` / `bun.lockb` is present, and runs `php artisan checkpoint:scan --json` with the report uploaded as an artifact. Pass `--force` to overwrite an existing file.

### GitLab CI

```bash
php artisan checkpoint:gitlab
```

Creates `.gitlab-ci.yml` — runs on merge requests and default-branch pushes using the `composer:2` image with a Composer cache, optional Node when a lockfile is present, JSON output, and a report artifact. If you already have a `.gitlab-ci.yml`, the command refuses to overwrite and prints the snippet to stdout so you can paste it into your existing pipeline. Use `--force` to overwrite.

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

> **Why only `post-*`, not `pre-*`?** Composer's `pre-update-cmd` fires _before_ dependencies are resolved, so the scanner would only see the codebase pre-update — useless against a malicious package that's about to be installed. And on a fresh clone there is no `vendor/`, so `php artisan` does not exist yet and `pre-install-cmd` would crash. Real-time interception of malicious installs is the job of [Docker](#docker-recommended) (preferred) and [Safe-Chain](#safe-chain-recommended) on the host.

### Exit codes

| Code | Meaning                                                                 |
| ---- | ----------------------------------------------------------------------- |
| `0`  | All checks passed (or warnings only, unless `--fail-on-warn` is set)    |
| `1`  | At least one check returned `FAIL`, or a `WARN` with `--fail-on-warn` |

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
    ├── SuspiciousVendorAutoloadCheck.php
    ├── SupplyChainToolingCheck.php
    ├── PathTraversalCheck.php
    ├── WeakCryptographyCheck.php
    ├── InsecureRngCheck.php
    ├── SessionSecurityCheck.php
    ├── EolVersionCheck.php
    ├── OutdatedPackagesCheck.php
    ├── AbandonedPackagesCheck.php
    ├── ComposerConfigCheck.php
    ├── XxeCheck.php
    ├── PhpCveCheck.php
    ├── PhpIniCheck.php
    └── PublicExposureCheck.php
resources/
└── php-advisories.php              # bundled PHP security releases + CVEs (generated)
scripts/
└── update-php-advisories.php       # regenerates the database from php.net
```

### Updating the PHP advisory database

`resources/php-advisories.php` is generated — do not edit it by hand. After a PHP security release, run:

```bash
php scripts/update-php-advisories.php
```

It rebuilds the file from the php.net changelog and release feed. Between Checkpoint releases, the live lookup covers the gap.

---

## Security

To report a vulnerability, see [SECURITY.md](SECURITY.md). Do not open a public issue.

## License

MIT — [Andrea Pollastri](https://andreapollastri.net)
