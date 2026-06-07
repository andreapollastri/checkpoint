<?php

namespace Checkpoint\Tests\Unit;

use Checkpoint\Checks\AbstractCheck;
use Checkpoint\Checks\CheckResult;
use Checkpoint\Checks\HardcodedSecretsCheck;
use Checkpoint\Checks\NpmAuditCheck;
use Checkpoint\Scanner;
use Checkpoint\Tests\TestCase;

class ScannerTest extends TestCase
{
    public function test_add_is_fluent_and_runs_each_registered_check(): void
    {
        $scanner = new Scanner();

        $returned = $scanner->add($this->fakeCheck('Alpha', CheckResult::pass('a')));
        $scanner->add($this->fakeCheck('Beta', CheckResult::fail('b')));

        $this->assertInstanceOf(Scanner::class, $returned);

        $results = $scanner->run();

        $this->assertSame(['Alpha', 'Beta'], array_keys($results));
        $this->assertSame(CheckResult::PASS, $results['Alpha']->status);
        $this->assertSame(CheckResult::FAIL, $results['Beta']->status);
    }

    public function test_run_keys_results_by_check_name(): void
    {
        $scanner = (new Scanner())->add($this->fakeCheck('Custom Name', CheckResult::warn('w')));

        $results = $scanner->run();

        $this->assertArrayHasKey('Custom Name', $results);
    }

    public function test_with_default_checks_registers_every_enabled_check(): void
    {
        $workspace = $this->makeWorkspace();

        $scanner = Scanner::withDefaultChecks($workspace);
        $results = $scanner->run();

        // The config ships 26 default checks, all enabled out of the box.
        $this->assertCount(26, $results);
        $this->assertArrayHasKey('Hardcoded Secrets', $results);
        $this->assertArrayHasKey('SQL Injection Risks', $results);
        $this->assertArrayHasKey('EOL Versions', $results);
    }

    public function test_with_default_checks_skips_checks_disabled_in_config(): void
    {
        config()->set('checkpoint.checks', [
            HardcodedSecretsCheck::class => false,
            NpmAuditCheck::class => false,
        ]);

        $workspace = $this->makeWorkspace();
        $results = Scanner::withDefaultChecks($workspace)->run();

        $this->assertArrayNotHasKey('Hardcoded Secrets', $results);
        $this->assertArrayNotHasKey('NPM CVE Audit', $results);
        // A check not mentioned in the (partial) map still defaults to enabled.
        $this->assertArrayHasKey('SQL Injection Risks', $results);
    }

    private function fakeCheck(string $name, CheckResult $result): AbstractCheck
    {
        return new class($name, $result) extends AbstractCheck
        {
            public function __construct(private string $checkName, private CheckResult $checkResult) {}

            public function name(): string
            {
                return $this->checkName;
            }

            public function run(): CheckResult
            {
                return $this->checkResult;
            }
        };
    }
}
