<?php

namespace Checkpoint\Checks;

class EolVersionCheck extends AbstractCheck
{
    // EOL cutoffs (as of 2026-05). FAIL = no security fixes at all.
    // WARN = security fixes ending within ~12 months.
    private const PHP_WARN_BELOW = 80300;      // PHP 8.2 → security ends Dec 2026

    private const LARAVEL_EOL_MAJOR = 11;      // Laravel < 11 → EOL; Laravel 11 → security ended Mar 2026

    private const LARAVEL_WARN_MAJOR = 12;     // Laravel 11 → warn

    public function __construct(private readonly string $basePath) {}

    public function name(): string
    {
        return 'EOL Versions';
    }

    public function run(): CheckResult
    {
        $findings = [];
        $hasCritical = false;

        // ---- PHP ----
        // Package floor is PHP 8.2, so older unsupported versions cannot install this scanner.
        if (PHP_VERSION_ID < self::PHP_WARN_BELOW) {
            $findings[] = 'PHP '.PHP_VERSION.' is in security-only support and approaches end-of-life. Plan upgrade to 8.3+.';
        }

        // ---- Laravel ----
        $lockPath = $this->basePath.'/composer.lock';
        if (file_exists($lockPath)) {
            $lock = @json_decode((string) file_get_contents($lockPath), true);
            if (is_array($lock)) {
                $packages = array_merge($lock['packages'] ?? [], $lock['packages-dev'] ?? []);
                foreach ($packages as $pkg) {
                    if (($pkg['name'] ?? null) !== 'laravel/framework') {
                        continue;
                    }

                    $version = ltrim((string) ($pkg['version'] ?? ''), 'v');
                    if (! preg_match('/^(\d+)/', $version, $m)) {
                        break;
                    }
                    $major = (int) $m[1];

                    if ($major > 0 && $major < self::LARAVEL_EOL_MAJOR) {
                        $findings[] = "Laravel {$version} is end-of-life — no security fixes. Upgrade to Laravel ".self::LARAVEL_EOL_MAJOR.'+ as soon as possible.';
                        $hasCritical = true;
                    } elseif ($major < self::LARAVEL_WARN_MAJOR) {
                        $findings[] = "Laravel {$version} is in security-only support and approaches end-of-life. Plan upgrade to Laravel ".self::LARAVEL_WARN_MAJOR.'+.';
                    }
                    break;
                }
            }
        }

        if (empty($findings)) {
            return CheckResult::pass('PHP and Laravel versions are within their security-supported window.');
        }

        $message = count($findings).' end-of-life or near-EOL version(s) detected.';

        return $hasCritical
            ? CheckResult::fail($message, $findings)
            : CheckResult::warn($message, $findings);
    }
}
