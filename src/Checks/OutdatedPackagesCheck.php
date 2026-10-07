<?php

namespace Checkpoint\Checks;

use Illuminate\Support\Str;
use Symfony\Component\Process\Process;

class OutdatedPackagesCheck extends AbstractCheck
{
    /**
     * @param  string[]  $ignore  Package names to skip; `*` wildcards allowed (e.g. `acme/*`).
     */
    public function __construct(
        private readonly string $basePath,
        private readonly array $ignore = [],
        private readonly bool $includeDev = false,
    ) {}

    public function name(): string
    {
        return 'Outdated Composer Packages';
    }

    public function run(): CheckResult
    {
        if (! file_exists($this->basePath.'/composer.lock')) {
            return CheckResult::warn('composer.lock not found — run `composer install` first.');
        }

        $report = $this->composerOutdated($error);

        if ($report === null) {
            return CheckResult::warn(
                'Could not run `composer outdated` — make sure Composer is on PATH and Packagist is reachable.',
                $error !== '' ? [$error] : [],
            );
        }

        $findings = [];
        $hashes = [];
        $safe = 0;
        $major = 0;

        foreach ($report['locked'] ?? $report['installed'] ?? [] as $package) {
            $name = $package['name'] ?? null;
            $version = $package['version'] ?? '?';
            $latest = $package['latest'] ?? null;
            $status = $package['latest-status'] ?? 'up-to-date';

            if (! $name || ! $latest || $status === 'up-to-date' || $this->isIgnored($name)) {
                continue;
            }

            if ($status === 'semver-safe-update') {
                $safe++;
                $kind = 'minor/patch';
            } else {
                $major++;
                $kind = 'major';
            }

            $detail = "{$name} {$version} → {$latest} ({$kind})";
            $findings[] = $detail;
            // Hash package + installed version only so suppressions survive new upstream releases.
            $hashes[$detail] = CheckResult::hashFinding($this->name(), "{$name} {$version}");
        }

        $scope = $this->includeDev ? 'direct' : 'direct production';

        if (empty($findings)) {
            return CheckResult::pass("All {$scope} Composer dependencies are on their latest release.");
        }

        $message = count($findings)." {$scope} Composer package(s) behind their latest release ({$safe} minor/patch, {$major} major) — minor/patch updates often include security fixes.";

        return CheckResult::warn($message, $findings, $hashes);
    }

    /**
     * Run `composer outdated` against composer.lock (works without vendor/).
     *
     * @return array<string, mixed>|null  Decoded JSON report, or null when Composer failed.
     */
    protected function composerOutdated(?string &$error = null): ?array
    {
        $command = ['composer', 'outdated', '--locked', '--direct', '--format=json', '--no-interaction'];

        if (! $this->includeDev) {
            $command[] = '--no-dev';
        }

        $process = new Process($command, $this->basePath, timeout: 120);
        $process->run();

        $error = self::firstLine($process->getErrorOutput(), self::COMPOSER_NOISE);
        $output = json_decode($process->getOutput(), true);

        return is_array($output) ? $output : null;
    }

    private function isIgnored(string $package): bool
    {
        foreach ($this->ignore as $pattern) {
            if (Str::is($pattern, $package)) {
                return true;
            }
        }

        return false;
    }
}
