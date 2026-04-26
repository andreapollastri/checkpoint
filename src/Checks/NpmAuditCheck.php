<?php

namespace Checkpoint\Checks;

use Symfony\Component\Process\Process;

class NpmAuditCheck extends AbstractCheck
{
    public function __construct(private readonly string $basePath) {}

    public function name(): string
    {
        return 'NPM CVE Audit';
    }

    public function run(): CheckResult
    {
        if (! file_exists($this->basePath.'/package.json')) {
            return CheckResult::warn('package.json not found — skipping NPM audit.');
        }

        $hasLock = file_exists($this->basePath.'/package-lock.json')
            || file_exists($this->basePath.'/yarn.lock')
            || file_exists($this->basePath.'/pnpm-lock.yaml');

        if (! $hasLock) {
            return CheckResult::warn('No lock file found (package-lock.json / yarn.lock / pnpm-lock.yaml) — skipping NPM audit.');
        }

        $process = new Process(['npm', 'audit', '--json'], $this->basePath, timeout: 120);
        $process->run();

        $output = @json_decode($process->getOutput(), true) ?? [];
        $vulnerabilities = $output['vulnerabilities'] ?? [];

        $critical = 0;
        $high = 0;
        $details = [];

        foreach ($vulnerabilities as $name => $vuln) {
            $severity = $vuln['severity'] ?? 'unknown';
            if ($severity === 'critical') {
                $critical++;
            }
            if ($severity === 'high') {
                $high++;
            }
            if (in_array($severity, ['critical', 'high'], true)) {
                $via = collect($vuln['via'] ?? [])->filter(fn ($v) => is_array($v))->first();
                $title = is_array($via) ? ($via['title'] ?? $name) : $name;
                $details[] = "[{$severity}] {$name}: {$title}";
            }
        }

        if ($critical > 0) {
            return CheckResult::fail("{$critical} critical vulnerability/ies in NPM dependencies.", $details);
        }

        if ($high > 0) {
            return CheckResult::warn("{$high} high-severity vulnerability/ies in NPM dependencies.", $details);
        }

        $total = count($vulnerabilities);
        if ($total > 0) {
            return CheckResult::warn("{$total} low/medium vulnerability/ies in NPM dependencies (run `npm audit` for details).");
        }

        return CheckResult::pass('No known CVEs in NPM dependencies.');
    }
}
