<?php

namespace Checkpoint\Checks;

class AbandonedPackagesCheck extends AbstractCheck
{
    public function __construct(private readonly string $basePath) {}

    public function name(): string
    {
        return 'Abandoned Composer Packages';
    }

    public function run(): CheckResult
    {
        $lockPath = $this->basePath.'/composer.lock';

        if (! file_exists($lockPath)) {
            return CheckResult::warn('composer.lock not found — run `composer install` first.');
        }

        $lock = @json_decode((string) file_get_contents($lockPath), true);
        if (! is_array($lock)) {
            return CheckResult::warn('composer.lock is not valid JSON — skipping abandoned package check.');
        }

        $findings = [];

        foreach (['packages', 'packages-dev'] as $section) {
            foreach ($lock[$section] ?? [] as $package) {
                $name = $package['name'] ?? null;
                $abandoned = $package['abandoned'] ?? false;

                if (! $name || $abandoned === false) {
                    continue;
                }

                $replacement = is_string($abandoned) && $abandoned !== ''
                    ? "use {$abandoned} instead"
                    : 'no replacement suggested';
                $scope = $section === 'packages-dev' ? ' [dev]' : '';
                $findings[] = "{$name} is abandoned — {$replacement}{$scope}";
            }
        }

        if (empty($findings)) {
            return CheckResult::pass('No abandoned packages in composer.lock.');
        }

        $message = count($findings).' abandoned Composer package(s) — they no longer receive security fixes. Migrate to a maintained alternative.';

        return CheckResult::warn($message, $findings);
    }
}
