<?php

namespace Checkpoint\Checks;

class EolVersionCheck extends AbstractCheck
{
    // End of security support per branch. FAIL once the date has passed,
    // WARN when it falls within WARN_WINDOW_DAYS. Versions older than the
    // first entry are treated as EOL; versions newer than the last as supported.
    // Sources: php.net/supported-versions, laravel.com/docs/releases#support-policy.
    private const PHP_SECURITY_EOL = [
        '8.1' => '2025-12-31',
        '8.2' => '2026-12-31',
        '8.3' => '2027-12-31',
        '8.4' => '2028-12-31',
        '8.5' => '2029-12-31',
    ];

    private const LARAVEL_SECURITY_EOL = [
        '10' => '2025-02-04',
        '11' => '2026-03-12',
        '12' => '2027-02-24',
        '13' => '2028-03-17',
    ];

    private const WARN_WINDOW_DAYS = 365;

    public function __construct(
        private readonly string $basePath,
        private readonly ?string $phpVersion = null,
        private readonly ?int $now = null,
    ) {}

    public function name(): string
    {
        return 'EOL Versions';
    }

    public function run(): CheckResult
    {
        $findings = [];
        $hasCritical = false;

        // ---- PHP ----
        $php = $this->phpVersion ?? PHP_VERSION;
        if (preg_match('/^(\d+)\.(\d+)/', $php, $m)) {
            $status = $this->status(self::PHP_SECURITY_EOL, "{$m[1]}.{$m[2]}");
            $target = 'PHP '.$this->upgradeTarget(self::PHP_SECURITY_EOL).'+';

            if ($status['eol']) {
                $findings[] = "PHP {$php} is end-of-life{$status['since']} — no security fixes from upstream. Upgrade to {$target} as soon as possible.";
                $hasCritical = true;
            } elseif ($status['warn']) {
                $findings[] = "PHP {$php} receives security fixes only until {$status['date']}. Plan an upgrade to {$target}.";
            }
        }

        // ---- Laravel ----
        $version = $this->lockedVersion('laravel/framework');
        if ($version !== null && preg_match('/^(\d+)/', $version, $m) && (int) $m[1] > 0) {
            $status = $this->status(self::LARAVEL_SECURITY_EOL, $m[1]);
            $target = 'Laravel '.$this->upgradeTarget(self::LARAVEL_SECURITY_EOL).'+';

            if ($status['eol']) {
                $findings[] = "Laravel {$version} is end-of-life{$status['since']} — no security fixes. Upgrade to {$target} as soon as possible.";
                $hasCritical = true;
            } elseif ($status['warn']) {
                $findings[] = "Laravel {$version} receives security fixes only until {$status['date']}. Plan an upgrade to {$target}.";
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

    /**
     * @param  array<string, string>  $table  branch => security EOL date
     * @return array{eol: bool, warn: bool, date: string, since: string}
     */
    private function status(array $table, string $branch): array
    {
        $date = $table[$branch] ?? null;

        if ($date === null) {
            // Unknown branch: older than the table → EOL, newer → supported.
            $eol = version_compare($branch, (string) array_key_first($table), '<');

            return ['eol' => $eol, 'warn' => false, 'date' => '', 'since' => ''];
        }

        $now = $this->now ?? time();
        $ends = (int) strtotime($date.' 23:59:59 UTC');

        return [
            'eol' => $now > $ends,
            'warn' => $now <= $ends && $ends - $now <= self::WARN_WINDOW_DAYS * 86400,
            'date' => $date,
            'since' => " since {$date}",
        ];
    }

    /**
     * Oldest branch that stays supported beyond the warn window.
     *
     * @param  array<string, string>  $table
     */
    private function upgradeTarget(array $table): string
    {
        foreach (array_keys($table) as $branch) {
            $status = $this->status($table, (string) $branch);

            if (! $status['eol'] && ! $status['warn']) {
                return (string) $branch;
            }
        }

        return (string) array_key_last($table);
    }

    private function lockedVersion(string $package): ?string
    {
        $lockPath = $this->basePath.'/composer.lock';
        if (! file_exists($lockPath)) {
            return null;
        }

        $lock = @json_decode((string) file_get_contents($lockPath), true);
        if (! is_array($lock)) {
            return null;
        }

        foreach (array_merge($lock['packages'] ?? [], $lock['packages-dev'] ?? []) as $pkg) {
            if (($pkg['name'] ?? null) === $package) {
                return ltrim((string) ($pkg['version'] ?? ''), 'v');
            }
        }

        return null;
    }
}
