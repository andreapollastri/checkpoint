# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.3.0] - 2026-11-19

### Added

- **PHP 8.6 support** — the suite passes on PHP 8.6 with no deprecations; EOL Versions knows the 8.6 branch (security support until 2030-12-31)
- **PHP CVE Audit** check — matches the running PHP version against a bundled database of PHP security releases and the CVE / GHSA advisories each one fixes (generated from the php.net changelog, 8.1 onwards), plus the live php.net release feed for security releases newer than the bundle. Fails on missing security releases and end-of-life branches; warns on pre-release builds, on Ubuntu builds (fixes may be backported) and when php.net is unreachable. `php_cve.live_lookup` config
- **PHP Configuration (php.ini)** check — audits the CLI runtime, `public/.user.ini`, the web-SAPI `php.ini` next to the CLI one on Debian / Ubuntu, and any file listed in `php_ini.files` for `allow_url_include` (FAIL), `display_errors`, `display_startup_errors`, `expose_php`, `zend.exception_ignore_args`, `error_include_args` (PHP 8.6), `auto_prepend_file` / `auto_append_file`, `cgi.force_redirect` and active Xdebug
- **Public Directory Exposure** check — flags `.env`, `.git`, `phpinfo()` scripts, Adminer / phpMyAdmin and database dumps under `public/`, PHP files in `storage/app/public`, stray PHP entry points, backup archives, and an `index.php` / `.htaccess` in the project root
- `checkpoint:github --php=` option
- `scripts/update-php-advisories.php` to regenerate `resources/php-advisories.php` from php.net

### Changed

- The GitHub workflow stub (`checkpoint:github`) no longer pins PHP 8.2 (end-of-life on 2026-12-31): it uses the PHP version running the command, or `--php`

## [1.2.1] - 2026-10-07

### Fixed

- NPM CVE Audit no longer skips Bun projects: when `bun.lock` / `bun.lockb` is present (and no `package-lock.json`), dependencies are audited with `bun audit`; it warns if Bun cannot run

### Changed

- The GitHub workflow stub (`checkpoint:github`) sets up Bun when a Bun lockfile is present

## [1.2.0] - 2026-10-07

### Added

- **Outdated Composer Packages** check — runs `composer outdated --locked --direct` and warns about direct dependencies behind their latest release (minor/patch vs major); `outdated_packages.ignore` / `include_dev` config
- **Abandoned Composer Packages** check — flags packages marked abandoned in `composer.lock`, with the suggested replacement
- **Composer Configuration** check — flags `secure-http: false`, `disable-tls`, `http://` repositories, registry credentials in `composer.json`, `allow-plugins: true`, unstable `minimum-stability` without `prefer-stable`, `audit.block-insecure: false`, and advisories silenced via `audit.ignore`
- **XML External Entity (XXE) Risks** check — flags `LIBXML_NOENT`, `LIBXML_DTDLOAD`/`DTDATTR`, `libxml_disable_entity_loader(false)`, and DOM/XMLReader entity options
- `.gitignore` check requires `auth.json` and fails when `auth.json` is tracked by git
- Explicit `symfony/finder` and `symfony/process` requirements (previously only pulled in transitively)

### Fixed

- Composer CVE Audit no longer reports PASS when `composer audit` cannot run (Composer missing from PATH, no network, no `vendor/`); it now audits `composer.lock` via `--locked` and warns on failure
- NPM CVE Audit no longer reports PASS when npm is missing or `npm audit` errors (e.g. `ENOLOCK` on yarn/pnpm-only projects)
- EOL Versions uses dated support tables: Laravel 11 (security EOL 2026-03-12) now fails, and Laravel 12 warns within a year of its 2027-02-24 cutoff

### Changed

- EOL Versions finding messages include the cutoff date, so existing suppression hashes for that check change

## [1.1.8] - 2026-09-18

### Added

- `SECURITY.md` with supported versions and private vulnerability reporting
- Composer/Packagist maintainer metadata (`authors`, `homepage`, `support`)
- README Security section linking to the policy

## [1.1.7] - 2026-08-14

### Fixed

- Package Freshness suppression hashes are based on package name + version only, so they no longer change as the displayed release age increases ([#12](https://github.com/andreapollastri/checkpoint/issues/12))

### Added

- Optional per-detail `hashes` map on `CheckResult` so checks can override the suppression hash used by `checkpoint:scan`

## [1.1.6] - 2026-08-01

### Fixed

- Relative finding paths no longer strip repeated path segments via `str_replace()` on `basePath` (e.g. Docker/CI root `/app` + Laravel `app/`), which produced different suppression hashes locally vs CI ([#11](https://github.com/andreapollastri/checkpoint/issues/11))
- Added `AbstractCheck::relativePath()` (prefix-only strip) and use it across all file-based checks
- Regression tests for the `/app` + `app/...` path case

## [1.1.5] - 2026-07-21

### Added

- Progress bar during `checkpoint:scan` (shows current check name; skipped with `--json`)

### Changed

- Smaller ASCII logo in `checkpoint:scan` CLI output
- `--only` / `--skip` filter checks before they run (faster ad-hoc scans)

## [1.1.4] - 2026-07-21

### Added

- `--fail-on-warn` option on `checkpoint:scan` to exit with code `1` when warnings are present
- `extra_checks` config to register custom `AbstractCheck` subclasses alongside built-ins
- Netlify deploy for the docs site (`netlify.toml`); site moved under `docs/`
- Unit tests for Debug Functions, SQL Injection, and TLS Verification checks
- `CHANGELOG.md`

### Changed

- CI stubs (GitHub Actions / GitLab CI): optional Node/`npm ci` when a lockfile is present, JSON scan output, and report artifacts
- Docs for `--fail-on-warn`, custom checks via config, exit codes, and updated CI scaffolding behavior
- Website stats update

### Removed

- Root `index.html` (replaced by `docs/index.html`)

## [1.1.3] - 2026-07-13

### Fixed

- Mass Assignment check no longer flags models that simply omit local `$fillable` / `$guarded`
- Models without an explicit unsafe pattern are skipped; `protected $guarded = []` on abstract base models still warns for child inheritance risk
- Added tests for explicit `['*']` guarding and abstract base-model inheritance

## [1.1.2] - 2026-07-04

### Fixed

- Hardcoded Secrets: limit Laravel cast exemptions to secure casts only (`encrypted`, `encrypted:array`, `AsEncryptedArrayObject`, `AsEncryptedCollection`, and stringable class casts) ([#7](https://github.com/andreapollastri/checkpoint/pull/7))

### Changed

- Refactored Laravel cast detection in Hardcoded Secrets check

### Tests

- Coverage for encrypted and stringable class casts

### Chore

- Remove committed PHPUnit cache files; ignore `.phpunit.cache` ([#8](https://github.com/andreapollastri/checkpoint/pull/8))

## [1.1.1] - 2026-06-07

### Added

- Configurable `exclude_paths` for file-based scans (`ScanPaths` helper + config)
- PHPUnit test suite (feature + unit coverage for scanner, env, secrets, scan paths)

### Changed

- File-based checks now share path resolution via `ScanPaths`

## [1.1.0] - 2026-05-30

> Also tagged as `1.0.10` and `1.0.11` (same commit).

### Fixed

- CSRF check ignores Livewire forms (avoids false positives on Livewire components)

## [1.0.9] - 2026-05-30

### Fixed

- README: broken framework-support anchor, check names aligned with CLI, status badges ([#2](https://github.com/andreapollastri/checkpoint/pull/2))
- Website: contain install block on small screens ([#1](https://github.com/andreapollastri/checkpoint/pull/1))

## [1.0.8] - 2026-05-25

### Added

- **Suspicious Vendor Autoload** check — flags `vendor/` packages that register PHP via `autoload.files` outside a whitelist (May 2026 Laravel-Lang supply-chain vector)
- `suspicious_autoload` whitelist in config

### Changed

- README companion-tooling guidance (Docker + Safe-Chain)
- Website UI/markup cleanups

## [1.0.7] - 2026-05-23

### Changed

- Clarify finding-hash suppression docs in `config/checkpoint.php`

## [1.0.6] - 2026-05-23

### Added

- **Path Traversal** check
- **Weak Cryptography** check
- **Insecure RNG** check
- **Session & Cookie Security** check
- **EOL Versions** check

### Changed

- Coverage documented as 25 checks; website example output and suppression guidance updated
- Package freshness whitelist includes Checkpoint itself

## [1.0.5] - 2026-05-23

### Added

- **SSRF** check
- **TLS Certificate Verification** check
- **CORS Configuration** check
- **Package Freshness (Supply Chain)** check
- **Supply Chain Tooling** check
- Publishable `config/checkpoint.php` (enable/disable checks, freshness whitelist/threshold)
- CI scaffolding: `checkpoint:github-pipeline` / `checkpoint:gitlab-pipeline` + workflow stubs
- Project website

### Changed

- Scanner builds checks from configurable factories

## [1.0.4] - 2026-05-23

### Fixed

- Fewer false positives in Deserialization (`allowed_classes`), Mass Assignment (Laravel 11 `Fillable`/`Guarded` attributes), and Hardcoded Secrets (validation rule strings)

### Changed

- Docs and website updates

## [1.0.3] - 2026-04-27

### Changed

- Improved Laravel 13 support

## [1.0.2] - 2026-04-27

### Fixed

- Laravel support fixes

### Changed

- Project cleanup and documentation

## [1.0.1] - 2026-04-27

### Fixed

- Dependency constraints

## [1.0.0] - 2026-04-27

### Added

- Initial release of Checkpoint — Laravel security scanner via `php artisan checkpoint:scan`
- Core checks: Composer/NPM CVE audit, environment config, `.gitignore`, file permissions, hardcoded secrets, SQL injection, mass assignment, XSS, CSRF, open redirect, command injection, insecure deserialization, debug functions, sensitive data exposure

### Changed

- Hardened Hardcoded Secrets detection before the first tagged release

[Unreleased]: https://github.com/andreapollastri/checkpoint/compare/1.2.1...HEAD
[1.2.1]: https://github.com/andreapollastri/checkpoint/compare/1.2.0...1.2.1
[1.2.0]: https://github.com/andreapollastri/checkpoint/compare/1.1.8...1.2.0
[1.1.8]: https://github.com/andreapollastri/checkpoint/compare/1.1.7...1.1.8
[1.1.7]: https://github.com/andreapollastri/checkpoint/compare/1.1.6...1.1.7
[1.1.6]: https://github.com/andreapollastri/checkpoint/compare/1.1.5...1.1.6
[1.1.5]: https://github.com/andreapollastri/checkpoint/compare/1.1.4...1.1.5
[1.1.4]: https://github.com/andreapollastri/checkpoint/compare/1.1.3...1.1.4
[1.1.3]: https://github.com/andreapollastri/checkpoint/compare/1.1.2...1.1.3
[1.1.2]: https://github.com/andreapollastri/checkpoint/compare/1.1.1...1.1.2
[1.1.1]: https://github.com/andreapollastri/checkpoint/compare/1.1.0...1.1.1
[1.1.0]: https://github.com/andreapollastri/checkpoint/compare/1.0.9...1.1.0
[1.0.9]: https://github.com/andreapollastri/checkpoint/compare/1.0.8...1.0.9
[1.0.8]: https://github.com/andreapollastri/checkpoint/compare/1.0.7...1.0.8
[1.0.7]: https://github.com/andreapollastri/checkpoint/compare/1.0.6...1.0.7
[1.0.6]: https://github.com/andreapollastri/checkpoint/compare/1.0.5...1.0.6
[1.0.5]: https://github.com/andreapollastri/checkpoint/compare/1.0.4...1.0.5
[1.0.4]: https://github.com/andreapollastri/checkpoint/compare/1.0.3...1.0.4
[1.0.3]: https://github.com/andreapollastri/checkpoint/compare/1.0.2...1.0.3
[1.0.2]: https://github.com/andreapollastri/checkpoint/compare/1.0.1...1.0.2
[1.0.1]: https://github.com/andreapollastri/checkpoint/compare/1.0.0...1.0.1
[1.0.0]: https://github.com/andreapollastri/checkpoint/releases/tag/1.0.0
