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

    public function test_only_keeps_matching_checks(): void
    {
        $scanner = (new Scanner())
            ->add($this->fakeCheck('Alpha', CheckResult::pass('a')))
            ->add($this->fakeCheck('Beta', CheckResult::pass('b')))
            ->only(['beta']);

        $this->assertSame(['Beta'], array_map(fn ($check) => $check->name(), $scanner->checks()));
        $this->assertSame(['Beta'], array_keys($scanner->run()));
    }

    public function test_except_drops_matching_checks(): void
    {
        $scanner = (new Scanner())
            ->add($this->fakeCheck('Alpha', CheckResult::pass('a')))
            ->add($this->fakeCheck('Beta', CheckResult::pass('b')))
            ->except(['Alpha']);

        $this->assertSame(['Beta'], array_keys($scanner->run()));
    }

    public function test_run_invokes_before_each_callback(): void
    {
        $seen = [];

        (new Scanner())
            ->add($this->fakeCheck('Alpha', CheckResult::pass('a')))
            ->add($this->fakeCheck('Beta', CheckResult::pass('b')))
            ->run(function (AbstractCheck $check) use (&$seen): void {
                $seen[] = $check->name();
            });

        $this->assertSame(['Alpha', 'Beta'], $seen);
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

    public function test_extra_checks_from_config_are_registered(): void
    {
        $extra = new class extends AbstractCheck
        {
            public function name(): string
            {
                return 'Extra Custom Check';
            }

            public function run(): CheckResult
            {
                return CheckResult::pass('ok');
            }
        };

        config()->set('checkpoint.extra_checks', [$extra::class]);

        $workspace = $this->makeWorkspace();
        $results = Scanner::withDefaultChecks($workspace)->run();

        $this->assertArrayHasKey('Extra Custom Check', $results);
        $this->assertCount(27, $results);
    }

    public function test_extra_checks_can_be_disabled_via_checks_map(): void
    {
        $extra = new class extends AbstractCheck
        {
            public function name(): string
            {
                return 'Disabled Extra Check';
            }

            public function run(): CheckResult
            {
                return CheckResult::fail('should not run');
            }
        };

        config()->set('checkpoint.extra_checks', [$extra::class]);
        config()->set('checkpoint.checks', array_merge(
            (array) config('checkpoint.checks', []),
            [$extra::class => false],
        ));

        $workspace = $this->makeWorkspace();
        $results = Scanner::withDefaultChecks($workspace)->run();

        $this->assertArrayNotHasKey('Disabled Extra Check', $results);
    }

    public function test_extra_checks_accepting_base_path_are_instantiated(): void
    {
        $extra = new class('unused') extends AbstractCheck
        {
            public function __construct(private string $basePath) {}

            public function name(): string
            {
                return 'Base Path Extra Check';
            }

            public function run(): CheckResult
            {
                return CheckResult::pass($this->basePath);
            }
        };

        config()->set('checkpoint.extra_checks', [$extra::class]);

        $workspace = $this->makeWorkspace();
        $results = Scanner::withDefaultChecks($workspace)->run();

        $this->assertArrayHasKey('Base Path Extra Check', $results);
        $this->assertSame($workspace, $results['Base Path Extra Check']->message);
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
