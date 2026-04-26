<?php

namespace Checkpoint\Checks;

use Symfony\Component\Process\Process;

class ComposerAuditCheck extends AbstractCheck
{
    public function __construct(private readonly string $basePath) {}

    public function name(): string
    {
        return 'Composer CVE Audit';
    }

    public function run(): CheckResult
    {
        if (! file_exists($this->basePath.'/composer.lock')) {
            return CheckResult::warn('composer.lock not found — run `composer install` first.');
        }

        $process = new Process(
            ['composer', 'audit', '--format=json', '--no-interaction'],
            $this->basePath,
            timeout: 60
        );
        $process->run();

        $output = @json_decode($process->getOutput(), true) ?? [];
        $advisories = $output['advisories'] ?? [];

        if (empty($advisories)) {
            return CheckResult::pass('No known CVEs in Composer dependencies.');
        }

        $details = [];
        foreach ($advisories as $package => $issues) {
            foreach ($issues as $issue) {
                $cve = $issue['cve'] ?? $issue['advisoryId'] ?? 'n/a';
                $details[] = "[{$package}] {$issue['title']} ({$cve})";
            }
        }

        return CheckResult::fail(count($details).' CVE(s) found in Composer dependencies.', $details);
    }
}
