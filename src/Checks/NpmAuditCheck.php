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

        $output = $this->npmAudit($error);

        // No JSON means npm did not run (not on PATH, offline…) — never report that as "no CVEs".
        if ($output === null) {
            return CheckResult::warn(
                'Could not run `npm audit` — make sure npm is on PATH and the registry is reachable.',
                $error !== '' ? [$error] : [],
            );
        }

        // npm reports its own failures as JSON, e.g. ENOLOCK when only yarn.lock / pnpm-lock.yaml exists.
        if (isset($output['error'])) {
            $code = $output['error']['code'] ?? 'unknown';
            $details = [$output['error']['summary'] ?? 'npm audit failed.'];

            if ($code === 'ENOLOCK') {
                $details[] = 'Yarn / pnpm projects: run `yarn npm audit` or `pnpm audit` in CI, or add a package-lock.json.';
            }

            return CheckResult::warn("`npm audit` failed ({$code}) — dependencies were not audited.", $details);
        }

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

    /**
     * @return array<string, mixed>|null  Decoded JSON report, or null when npm failed.
     */
    protected function npmAudit(?string &$error = null): ?array
    {
        $process = new Process(['npm', 'audit', '--json'], $this->basePath, timeout: 120);
        $process->run();

        $error = self::firstLine($process->getErrorOutput(), ['npm warn']);
        $output = json_decode($process->getOutput(), true);

        return is_array($output) ? $output : null;
    }
}
