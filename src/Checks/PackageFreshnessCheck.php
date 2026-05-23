<?php

namespace Checkpoint\Checks;

class PackageFreshnessCheck extends AbstractCheck
{
    /**
     * @param  string[]  $whitelist  Fully-qualified package names (vendor/pkg) to skip.
     */
    public function __construct(
        private readonly string $basePath,
        private readonly int $minimumAgeDays = 3,
        private readonly array $whitelist = [],
    ) {}

    public function name(): string
    {
        return 'Package Freshness (Supply Chain)';
    }

    public function run(): CheckResult
    {
        $lockPath = $this->basePath.'/composer.lock';

        if (! file_exists($lockPath)) {
            return CheckResult::warn('composer.lock not found — run `composer install` first.');
        }

        $lock = @json_decode((string) file_get_contents($lockPath), true);
        if (! is_array($lock)) {
            return CheckResult::warn('composer.lock is not valid JSON — skipping freshness check.');
        }

        $threshold = time() - ($this->minimumAgeDays * 86400);
        $whitelist = array_flip($this->whitelist);
        $findings = [];
        $skipped = 0;

        foreach (['packages', 'packages-dev'] as $section) {
            foreach ($lock[$section] ?? [] as $package) {
                $name = $package['name'] ?? null;
                $version = $package['version'] ?? '?';
                $time = $package['time'] ?? null;

                if (! $name || ! $time) {
                    continue;
                }

                $releasedAt = strtotime($time);
                if ($releasedAt === false || $releasedAt < $threshold) {
                    continue;
                }

                if (isset($whitelist[$name])) {
                    $skipped++;
                    continue;
                }

                $ageHours = max(0, (int) floor((time() - $releasedAt) / 3600));
                $scope = $section === 'packages-dev' ? ' [dev]' : '';
                $findings[] = "{$name} {$version} released {$ageHours}h ago{$scope}";
            }
        }

        if (empty($findings)) {
            $note = $skipped > 0
                ? " ({$skipped} whitelisted package(s) skipped)"
                : '';

            return CheckResult::pass("All Composer packages are older than {$this->minimumAgeDays} day(s){$note}.");
        }

        $message = count($findings)." Composer package(s) released within the last {$this->minimumAgeDays} day(s) — whitelist in config/checkpoint.php if intentional.";

        return CheckResult::fail($message, $findings);
    }
}
