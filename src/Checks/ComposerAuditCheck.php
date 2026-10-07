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

        $output = $this->composerAudit($error);

        // No JSON means Composer did not run (not on PATH, offline, too old…) —
        // never report that as "no CVEs".
        if ($output === null) {
            return CheckResult::warn(
                'Could not run `composer audit` — make sure Composer is on PATH and Packagist is reachable.',
                $error !== '' ? [$error] : [],
            );
        }

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

    /**
     * Run `composer audit` against composer.lock (works without vendor/).
     *
     * @return array<string, mixed>|null  Decoded JSON report, or null when Composer failed.
     */
    protected function composerAudit(?string &$error = null): ?array
    {
        $process = new Process(
            ['composer', 'audit', '--locked', '--format=json', '--no-interaction'],
            $this->basePath,
            timeout: 60
        );
        $process->run();

        $error = self::firstLine($process->getErrorOutput(), self::COMPOSER_NOISE);
        $output = json_decode($process->getOutput(), true);

        return is_array($output) ? $output : null;
    }
}
