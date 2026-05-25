<?php

namespace Checkpoint\Checks;

class SuspiciousVendorAutoloadCheck extends AbstractCheck
{
    /**
     * Packages that legitimately register PHP functions via `autoload.files`.
     * Entries support a trailing `*` wildcard for vendor-wide allowlisting
     * (e.g. `symfony/polyfill-*`).
     *
     * Kept intentionally conservative: a false-positive WARN is cheap to
     * whitelist; a missed malicious package is not.
     */
    private const DEFAULT_WHITELIST = [
        'laravel/framework',
        'illuminate/*',
        'symfony/polyfill-*',
        'symfony/deprecation-contracts',
        'guzzlehttp/guzzle',
        'guzzlehttp/psr7',
        'guzzlehttp/promises',
        'ramsey/uuid',
        'ramsey/collection',
        'paragonie/random_compat',
        'paragonie/sodium_compat',
        'voku/portable-ascii',
        'composer/installers',
        'composer/semver',
        'swiftmailer/swiftmailer',
        'phpunit/php-timer',
        'phpunit/php-text-template',
        'webmozart/assert',
        'nesbot/carbon',
    ];

    /**
     * @param  string[]  $extraWhitelist  Additional `vendor/pkg` patterns to allow.
     */
    public function __construct(
        private readonly string $basePath,
        private readonly array $extraWhitelist = [],
    ) {}

    public function name(): string
    {
        return 'Suspicious Vendor Autoload';
    }

    public function run(): CheckResult
    {
        $vendorPath = $this->basePath.'/vendor';

        if (! is_dir($vendorPath)) {
            return CheckResult::warn('vendor/ not found — run `composer install` first.');
        }

        $whitelist = array_merge(self::DEFAULT_WHITELIST, $this->extraWhitelist);
        $findings = [];
        $scanned = 0;

        foreach ($this->vendorComposerFiles($vendorPath) as $package => $manifestPath) {
            $scanned++;

            $manifest = @json_decode((string) file_get_contents($manifestPath), true);
            if (! is_array($manifest)) {
                continue;
            }

            $files = array_merge(
                (array) ($manifest['autoload']['files'] ?? []),
                (array) ($manifest['autoload-dev']['files'] ?? []),
            );

            if (empty($files)) {
                continue;
            }

            if ($this->isWhitelisted($package, $whitelist)) {
                continue;
            }

            $list = implode(', ', array_slice($files, 0, 3));
            if (count($files) > 3) {
                $list .= ', …';
            }

            $findings[] = "{$package} — autoload.files: {$list}";
        }

        if (empty($findings)) {
            return CheckResult::pass("No unexpected `autoload.files` entries across {$scanned} vendor package(s).");
        }

        $message = count($findings).' vendor package(s) register code via `autoload.files` outside the known-safe whitelist — inspect the referenced files before trusting them, then add the package to `suspicious_autoload.whitelist` in config/checkpoint.php if intentional.';

        return CheckResult::warn($message, $findings);
    }

    /**
     * @return iterable<string, string>  vendor/package => absolute composer.json path
     */
    private function vendorComposerFiles(string $vendorPath): iterable
    {
        $vendors = @scandir($vendorPath) ?: [];

        foreach ($vendors as $vendor) {
            if ($vendor === '.' || $vendor === '..' || $vendor === 'bin' || $vendor === 'composer') {
                continue;
            }

            $vendorDir = $vendorPath.'/'.$vendor;
            if (! is_dir($vendorDir)) {
                continue;
            }

            $packages = @scandir($vendorDir) ?: [];
            foreach ($packages as $package) {
                if ($package === '.' || $package === '..') {
                    continue;
                }

                $manifest = $vendorDir.'/'.$package.'/composer.json';
                if (is_file($manifest)) {
                    yield "{$vendor}/{$package}" => $manifest;
                }
            }
        }
    }

    /**
     * @param  string[]  $whitelist
     */
    private function isWhitelisted(string $package, array $whitelist): bool
    {
        foreach ($whitelist as $pattern) {
            if ($pattern === $package) {
                return true;
            }

            if (str_ends_with($pattern, '*') && str_starts_with($package, substr($pattern, 0, -1))) {
                return true;
            }
        }

        return false;
    }
}
