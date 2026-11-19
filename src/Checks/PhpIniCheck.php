<?php

namespace Checkpoint\Checks;

class PhpIniCheck extends AbstractCheck
{
    private const DIRECTIVES = [
        'allow_url_include',
        'display_errors',
        'display_startup_errors',
        'expose_php',
        'zend.exception_ignore_args',
        'error_include_args',
        'auto_prepend_file',
        'auto_append_file',
        'cgi.force_redirect',
        'xdebug.mode',
        'xdebug.discover_client_host',
    ];

    /** Web SAPIs that keep their own php.ini next to the CLI one (Debian / Ubuntu layout). */
    private const SIBLING_SAPIS = ['fpm', 'apache2', 'cgi'];

    /** auto_prepend_file values set by local development tools. */
    private const KNOWN_PREPEND_FILES = '#[/\\\\]Herd(?:\.app)?[/\\\\].*dump-loader\.php$#';

    /**
     * @param  list<string>  $files  Extra php.ini files (or conf.d directories) to audit, e.g. the PHP-FPM one.
     * @param  array<string, string>|null  $runtime  Effective directives of this process; read via ini_get() when null.
     * @param  string|null  $loadedIniFile  php.ini of this process; php_ini_loaded_file() when null.
     */
    public function __construct(
        private readonly string $basePath,
        private readonly array $files = [],
        private readonly ?array $runtime = null,
        private readonly ?string $loadedIniFile = null,
    ) {}

    public function name(): string
    {
        return 'PHP Configuration (php.ini)';
    }

    public function run(): CheckResult
    {
        $failures = [];
        $warnings = [];
        $checked = [];

        foreach ($this->sources($warnings) as $label => $values) {
            $checked[] = $label;

            foreach ($this->evaluate($values) as [$critical, $finding]) {
                if ($critical) {
                    $failures[] = "{$label}: {$finding}";
                } else {
                    $warnings[] = "{$label}: {$finding}";
                }
            }
        }

        if ($failures === [] && $warnings === []) {
            return CheckResult::pass('PHP configuration looks hardened (checked: '.implode(', ', $checked).').');
        }

        $details = array_merge($failures, $warnings);
        $message = count($details).' PHP configuration issue(s) found.';

        return $failures !== []
            ? CheckResult::fail($message, $details)
            : CheckResult::warn($message, $details);
    }

    /**
     * @param  array<string, string>  $ini  Directives explicitly known for one source.
     * @return list<array{bool, string}>  [is critical, finding]
     */
    private function evaluate(array $ini): array
    {
        $on = static fn (string $directive): bool => isset($ini[$directive])
            && in_array(strtolower($ini[$directive]), ['1', 'on', 'yes', 'true'], true);

        $off = static fn (string $directive): bool => isset($ini[$directive])
            && in_array(strtolower($ini[$directive]), ['', '0', 'off', 'no', 'false', 'none'], true);

        $findings = [];

        if ($on('allow_url_include')) {
            $findings[] = [true, 'allow_url_include = On — include/require can load remote code (RFI); it is also the switch PHP-CGI argument-injection exploits flip (CVE-2012-1823, CVE-2024-4577). Set it to Off.'];
        }

        if ($on('display_errors') || strtolower($ini['display_errors'] ?? '') === 'stdout') {
            $findings[] = [false, 'display_errors = On — PHP errors (paths, queries, stack traces) are printed to visitors. Set it to Off and rely on log_errors.'];
        }

        if ($on('display_startup_errors')) {
            $findings[] = [false, 'display_startup_errors = On — startup errors are printed to visitors. Set it to Off.'];
        }

        if ($on('expose_php')) {
            $findings[] = [false, 'expose_php = On — the X-Powered-By header advertises the exact PHP version, which makes CVE fingerprinting trivial. Set it to Off.'];
        }

        if ($off('zend.exception_ignore_args')) {
            $findings[] = [false, 'zend.exception_ignore_args = Off — stack traces include function arguments, so passwords and tokens can leak into logs and error trackers. Set it to On.'];
        }

        if ($on('error_include_args')) {
            $findings[] = [false, 'error_include_args = On — error messages include the arguments of the failing call (PHP 8.6+), which can leak sensitive values into logs and error pages. Set it to Off.'];
        }

        foreach (['auto_prepend_file', 'auto_append_file'] as $directive) {
            if (isset($ini[$directive]) && ! $off($directive) && ! preg_match(self::KNOWN_PREPEND_FILES, $ini[$directive])) {
                $findings[] = [false, "{$directive} = \"{$ini[$directive]}\" — this file runs on every request. Make sure it is intentional: it is a common webshell persistence trick."];
            }
        }

        if ($off('cgi.force_redirect')) {
            $findings[] = [false, 'cgi.force_redirect = 0 — php-cgi can be requested directly, bypassing web-server access rules (CVE-2012-1823, CVE-2024-8927). Keep it at 1 unless you run IIS.'];
        }

        if (isset($ini['xdebug.mode']) && ! $off('xdebug.mode')) {
            $findings[] = [false, "xdebug.mode = {$ini['xdebug.mode']} — Xdebug is active. Do not load it in production: it slows every request and exposes debugging hooks."];
        }

        if ($on('xdebug.discover_client_host')) {
            $findings[] = [false, 'xdebug.discover_client_host = On — Xdebug connects back to whoever sends the request, handing them a step debugger (remote code execution) if this server is reachable by others.'];
        }

        return $findings;
    }

    /**
     * @param  list<string>  $warnings  Receives a finding for every configured file that cannot be read.
     * @return array<string, array<string, string>>  source label => directives
     */
    private function sources(array &$warnings): array
    {
        $sources = ['runtime ('.PHP_SAPI.')' => $this->runtime ?? $this->runtimeDirectives()];

        foreach ($this->siblingSapiFiles() as $label => $files) {
            $sources[$label] = $this->parse($files) ?? [];
        }

        if (is_file($this->basePath.'/public/.user.ini')) {
            $sources['public/.user.ini'] = $this->parse([$this->basePath.'/public/.user.ini']) ?? [];
        }

        foreach ($this->files as $path) {
            $absolute = preg_match('#^(?:/|[A-Za-z]:[\\\\/])#', $path) ? $path : $this->basePath.'/'.$path;
            $files = is_dir($absolute) ? (glob(rtrim($absolute, '/').'/*.ini') ?: []) : [$absolute];
            $directives = $this->parse($files);

            if ($directives === null) {
                $warnings[] = "{$path}: listed in `php_ini.files` but could not be read — this configuration was not audited.";

                continue;
            }

            $sources[$path] = $directives;
        }

        return $sources;
    }

    /**
     * @return array<string, string>
     */
    private function runtimeDirectives(): array
    {
        // Read the master value (php.ini + built-in default), not the current one:
        // Laravel calls ini_set('display_errors', 'Off') while booting, which
        // would hide what the server itself is configured with.
        $master = function_exists('ini_get_all') ? (@ini_get_all(null, true) ?: []) : [];
        $directives = [];

        foreach (self::DIRECTIVES as $directive) {
            $value = $master[$directive]['global_value'] ?? ini_get($directive);

            // Not a string: the directive is unset, or not registered in this
            // SAPI (cgi.*) / its extension is not loaded (xdebug.*).
            if (is_string($value)) {
                $directives[$directive] = $value;
            }
        }

        return $directives;
    }

    /**
     * On Debian / Ubuntu every SAPI has its own php.ini (/etc/php/8.4/{cli,fpm,…}),
     * so the CLI running this scan does not see what the web server uses.
     *
     * @return array<string, list<string>>  php.ini path => that file plus its conf.d/*.ini
     */
    private function siblingSapiFiles(): array
    {
        $loaded = $this->loadedIniFile ?? (php_ini_loaded_file() ?: '');

        if (basename($loaded) !== 'php.ini' || ! in_array(basename(dirname($loaded)), ['cli', ...self::SIBLING_SAPIS], true)) {
            return [];
        }

        $siblings = [];

        foreach (self::SIBLING_SAPIS as $sapi) {
            $ini = dirname($loaded, 2)."/{$sapi}/php.ini";

            if ($ini !== $loaded && is_readable($ini)) {
                $siblings[$ini] = [$ini, ...(glob(dirname($ini).'/conf.d/*.ini') ?: [])];
            }
        }

        return $siblings;
    }

    /**
     * Directives explicitly set across the given ini files (later files win).
     *
     * @param  list<string>  $files
     * @return array<string, string>|null  null when nothing could be read.
     */
    private function parse(array $files): ?array
    {
        $directives = [];
        $read = false;

        foreach ($files as $file) {
            $contents = is_readable($file) ? @file_get_contents($file) : false;
            $parsed = $contents !== false ? @parse_ini_string($contents, false, INI_SCANNER_RAW) : false;

            if ($parsed === false) {
                continue;
            }

            $read = true;

            foreach (self::DIRECTIVES as $directive) {
                if (isset($parsed[$directive]) && is_string($parsed[$directive])) {
                    $directives[$directive] = trim($parsed[$directive]);
                }
            }

            // Xdebug defaults to "develop" as soon as it is loaded.
            if (preg_match('/^\s*zend_extension\s*=\s*"?[^;\r\n]*xdebug/mi', $contents)) {
                $directives['xdebug.mode'] ??= 'develop';
            }
        }

        return $read ? $directives : null;
    }
}
