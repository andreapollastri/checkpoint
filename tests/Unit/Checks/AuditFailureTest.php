<?php

namespace Checkpoint\Tests\Unit\Checks;

use Checkpoint\Checks\CheckResult;
use Checkpoint\Checks\ComposerAuditCheck;
use Checkpoint\Checks\NpmAuditCheck;
use Checkpoint\Tests\TestCase;

/**
 * A tool that fails to run must never be reported as "no known CVEs".
 */
class AuditFailureTest extends TestCase
{
    public function test_composer_audit_warns_when_composer_produces_no_json(): void
    {
        $workspace = $this->makeWorkspace();
        $this->writeFile($workspace, 'composer.lock', '{"packages":[]}');

        $result = $this->composerAudit($workspace, null, 'composer: command not found')->run();

        $this->assertSame(CheckResult::WARN, $result->status);
        $this->assertStringContainsString('Could not run `composer audit`', $result->message);
        $this->assertSame(['composer: command not found'], $result->details);
    }

    public function test_composer_audit_passes_on_an_empty_report(): void
    {
        $workspace = $this->makeWorkspace();
        $this->writeFile($workspace, 'composer.lock', '{"packages":[]}');

        $result = $this->composerAudit($workspace, ['advisories' => [], 'abandoned' => []])->run();

        $this->assertSame(CheckResult::PASS, $result->status);
    }

    public function test_composer_audit_fails_on_advisories(): void
    {
        $workspace = $this->makeWorkspace();
        $this->writeFile($workspace, 'composer.lock', '{"packages":[]}');

        $result = $this->composerAudit($workspace, ['advisories' => [
            'acme/lib' => [['title' => 'RCE in parser', 'cve' => 'CVE-2026-0001']],
        ]])->run();

        $this->assertSame(CheckResult::FAIL, $result->status);
        $this->assertSame(['[acme/lib] RCE in parser (CVE-2026-0001)'], $result->details);
    }

    public function test_npm_audit_warns_when_npm_produces_no_json(): void
    {
        $workspace = $this->npmWorkspace('package-lock.json');

        $result = $this->npmAudit($workspace, null, 'sh: npm: command not found')->run();

        $this->assertSame(CheckResult::WARN, $result->status);
        $this->assertStringContainsString('Could not run `npm audit`', $result->message);
        $this->assertSame(['sh: npm: command not found'], $result->details);
    }

    public function test_npm_audit_warns_on_enolock_for_yarn_and_pnpm_projects(): void
    {
        $workspace = $this->npmWorkspace('yarn.lock');

        $result = $this->npmAudit($workspace, ['error' => [
            'code' => 'ENOLOCK',
            'summary' => 'This command requires an existing lockfile.',
        ]])->run();

        $this->assertSame(CheckResult::WARN, $result->status);
        $this->assertStringContainsString('ENOLOCK', $result->message);
        $this->assertStringContainsString('pnpm audit', $result->details[1]);
    }

    public function test_npm_audit_passes_on_an_empty_report(): void
    {
        $workspace = $this->npmWorkspace('package-lock.json');

        $result = $this->npmAudit($workspace, ['vulnerabilities' => []])->run();

        $this->assertSame(CheckResult::PASS, $result->status);
    }

    private function npmWorkspace(string $lockFile): string
    {
        $workspace = $this->makeWorkspace();
        $this->writeFile($workspace, 'package.json', '{"name":"app"}');
        $this->writeFile($workspace, $lockFile, '');

        return $workspace;
    }

    /**
     * @param  array<string, mixed>|null  $report
     */
    private function composerAudit(string $workspace, ?array $report, string $error = ''): ComposerAuditCheck
    {
        return new class($workspace, $report, $error) extends ComposerAuditCheck
        {
            public function __construct(string $basePath, private readonly ?array $report, private readonly string $fakeError)
            {
                parent::__construct($basePath);
            }

            protected function composerAudit(?string &$error = null): ?array
            {
                $error = $this->fakeError;

                return $this->report;
            }
        };
    }

    /**
     * @param  array<string, mixed>|null  $report
     */
    private function npmAudit(string $workspace, ?array $report, string $error = ''): NpmAuditCheck
    {
        return new class($workspace, $report, $error) extends NpmAuditCheck
        {
            public function __construct(string $basePath, private readonly ?array $report, private readonly string $fakeError)
            {
                parent::__construct($basePath);
            }

            protected function npmAudit(?string &$error = null): ?array
            {
                $error = $this->fakeError;

                return $this->report;
            }
        };
    }
}
