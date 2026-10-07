<?php

namespace Checkpoint\Checks;

use Symfony\Component\Process\Process;

class NpmAuditCheck extends AbstractCheck
{
    private const SEVERITY_RANK = ['info' => 0, 'low' => 1, 'moderate' => 2, 'high' => 3, 'critical' => 4];

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

        $hasNpmLock = file_exists($this->basePath.'/package-lock.json');
        $hasBunLock = file_exists($this->basePath.'/bun.lock') || file_exists($this->basePath.'/bun.lockb');

        // npm cannot read Bun's lockfile, so a Bun-only project is audited with `bun audit`.
        if ($hasBunLock && ! $hasNpmLock) {
            return $this->runBunAudit();
        }

        $hasLock = $hasNpmLock
            || file_exists($this->basePath.'/yarn.lock')
            || file_exists($this->basePath.'/pnpm-lock.yaml');

        if (! $hasLock) {
            return CheckResult::warn('No lock file found (package-lock.json / yarn.lock / pnpm-lock.yaml / bun.lock) — skipping NPM audit.');
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

        $packages = [];

        foreach ($output['vulnerabilities'] ?? [] as $name => $vuln) {
            $via = collect($vuln['via'] ?? [])->filter(fn ($v) => is_array($v))->first();

            $packages[$name] = [
                'severity' => $vuln['severity'] ?? 'unknown',
                'title' => is_array($via) ? ($via['title'] ?? $name) : $name,
            ];
        }

        return $this->summarize($packages, 'npm audit');
    }

    private function runBunAudit(): CheckResult
    {
        $output = $this->bunAudit($error);

        // Bun prints failures (missing lockfile, registry unreachable…) to stderr and no JSON.
        if ($output === null) {
            return CheckResult::warn(
                'Could not run `bun audit` — make sure bun is on PATH and the registry is reachable.',
                $error !== '' ? [$error] : [],
            );
        }

        // Bulk advisory format: package name => list of advisories. Keep the most severe one per package.
        $packages = [];

        foreach ($output as $name => $advisories) {
            foreach (is_array($advisories) ? $advisories : [] as $advisory) {
                $severity = $advisory['severity'] ?? 'unknown';

                if (! isset($packages[$name]) || self::rank($severity) > self::rank($packages[$name]['severity'])) {
                    $packages[$name] = ['severity' => $severity, 'title' => $advisory['title'] ?? $name];
                }
            }
        }

        return $this->summarize($packages, 'bun audit');
    }

    /**
     * @param  array<string, array{severity: string, title: string}>  $packages  Vulnerable packages, one entry each.
     */
    private function summarize(array $packages, string $command): CheckResult
    {
        $critical = 0;
        $high = 0;
        $details = [];

        foreach ($packages as $name => $package) {
            $severity = $package['severity'];
            if ($severity === 'critical') {
                $critical++;
            }
            if ($severity === 'high') {
                $high++;
            }
            if (in_array($severity, ['critical', 'high'], true)) {
                $details[] = "[{$severity}] {$name}: {$package['title']}";
            }
        }

        if ($critical > 0) {
            return CheckResult::fail("{$critical} critical vulnerability/ies in NPM dependencies.", $details);
        }

        if ($high > 0) {
            return CheckResult::warn("{$high} high-severity vulnerability/ies in NPM dependencies.", $details);
        }

        $total = count($packages);
        if ($total > 0) {
            return CheckResult::warn("{$total} low/medium vulnerability/ies in NPM dependencies (run `{$command}` for details).");
        }

        return CheckResult::pass('No known CVEs in NPM dependencies.');
    }

    private static function rank(string $severity): int
    {
        return self::SEVERITY_RANK[$severity] ?? -1;
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

    /**
     * @return array<string, mixed>|null  Decoded bulk advisory report, or null when bun failed.
     */
    protected function bunAudit(?string &$error = null): ?array
    {
        $process = new Process(['bun', 'audit', '--json'], $this->basePath, timeout: 120);
        $process->run();

        $error = self::firstLine($process->getErrorOutput());
        $output = json_decode($process->getOutput(), true);

        return is_array($output) ? $output : null;
    }
}
