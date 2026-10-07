<?php

namespace Checkpoint\Tests\Unit\Checks;

use Checkpoint\Checks\CheckResult;
use Checkpoint\Checks\OutdatedPackagesCheck;
use Checkpoint\Tests\TestCase;

class OutdatedPackagesCheckTest extends TestCase
{
    private const NAME = 'Outdated Composer Packages';

    public function test_warns_when_composer_lock_is_missing(): void
    {
        $workspace = $this->makeWorkspace();

        $result = $this->check($workspace, ['locked' => []])->run();

        $this->assertSame(CheckResult::WARN, $result->status);
        $this->assertStringContainsString('composer.lock not found', $result->message);
    }

    public function test_warns_instead_of_passing_when_composer_cannot_run(): void
    {
        $workspace = $this->workspaceWithLock();

        $result = $this->check($workspace, null, error: 'The "--locked" option does not exist.')->run();

        $this->assertSame(CheckResult::WARN, $result->status);
        $this->assertStringContainsString('Could not run `composer outdated`', $result->message);
        $this->assertSame(['The "--locked" option does not exist.'], $result->details);
    }

    public function test_passes_when_nothing_is_outdated(): void
    {
        $workspace = $this->workspaceWithLock();

        $result = $this->check($workspace, ['locked' => []])->run();

        $this->assertSame(CheckResult::PASS, $result->status);
        $this->assertStringContainsString('direct production', $result->message);
    }

    public function test_warns_and_labels_minor_and_major_updates(): void
    {
        $workspace = $this->workspaceWithLock();

        $result = $this->check($workspace, ['locked' => [
            $this->package('laravel/framework', 'v12.10.0', 'v12.31.1', 'semver-safe-update'),
            $this->package('acme/sdk', '1.4.0', '2.0.0', 'update-possible'),
        ]])->run();

        $this->assertSame(CheckResult::WARN, $result->status);
        $this->assertStringContainsString('(1 minor/patch, 1 major)', $result->message);
        $this->assertSame([
            'laravel/framework v12.10.0 → v12.31.1 (minor/patch)',
            'acme/sdk 1.4.0 → 2.0.0 (major)',
        ], $result->details);
    }

    public function test_reads_the_installed_key_as_well(): void
    {
        $workspace = $this->workspaceWithLock();

        $result = $this->check($workspace, ['installed' => [
            $this->package('acme/sdk', '1.4.0', '1.5.0', 'semver-safe-update'),
        ]])->run();

        $this->assertSame(CheckResult::WARN, $result->status);
        $this->assertCount(1, $result->details);
    }

    public function test_skips_up_to_date_and_ignored_packages(): void
    {
        $workspace = $this->workspaceWithLock();

        $result = $this->check($workspace, ['locked' => [
            $this->package('acme/sdk', '1.4.0', '1.4.0', 'up-to-date'),
            $this->package('acme/pinned', '1.0.0', '3.0.0', 'update-possible'),
            $this->package('legacy/lib', '0.9.0', '1.0.0', 'update-possible'),
        ]], ignore: ['acme/*', 'legacy/lib'])->run();

        $this->assertSame(CheckResult::PASS, $result->status);
    }

    public function test_suppression_hash_survives_new_upstream_releases(): void
    {
        $workspace = $this->workspaceWithLock();

        $before = $this->check($workspace, ['locked' => [
            $this->package('acme/sdk', '1.4.0', '1.5.0', 'semver-safe-update'),
        ]])->run();
        $after = $this->check($workspace, ['locked' => [
            $this->package('acme/sdk', '1.4.0', '1.6.0', 'semver-safe-update'),
        ]])->run();

        $this->assertNotSame($before->details[0], $after->details[0]);
        $this->assertSame(
            CheckResult::hashFinding(self::NAME, 'acme/sdk 1.4.0'),
            $after->hashFor(self::NAME, $after->details[0]),
        );
        $this->assertSame(
            $before->hashFor(self::NAME, $before->details[0]),
            $after->hashFor(self::NAME, $after->details[0]),
        );
    }

    public function test_message_mentions_dev_scope_when_enabled(): void
    {
        $workspace = $this->workspaceWithLock();

        $result = $this->check($workspace, ['locked' => []], includeDev: true)->run();

        $this->assertStringContainsString('All direct Composer dependencies', $result->message);
    }

    private function workspaceWithLock(): string
    {
        $workspace = $this->makeWorkspace();
        $this->writeFile($workspace, 'composer.lock', '{"packages":[],"packages-dev":[]}');

        return $workspace;
    }

    /**
     * @return array<string, string>
     */
    private function package(string $name, string $version, string $latest, string $status): array
    {
        return [
            'name' => $name,
            'version' => $version,
            'latest' => $latest,
            'latest-status' => $status,
        ];
    }

    /**
     * @param  array<string, mixed>|null  $report  Fake `composer outdated --format=json` output.
     * @param  string[]  $ignore
     */
    private function check(
        string $workspace,
        ?array $report,
        array $ignore = [],
        bool $includeDev = false,
        string $error = '',
    ): OutdatedPackagesCheck {
        return new class($workspace, $ignore, $includeDev, $report, $error) extends OutdatedPackagesCheck
        {
            public function __construct(
                string $basePath,
                array $ignore,
                bool $includeDev,
                private readonly ?array $report,
                private readonly string $fakeError,
            ) {
                parent::__construct($basePath, $ignore, $includeDev);
            }

            protected function composerOutdated(?string &$error = null): ?array
            {
                $error = $this->fakeError;

                return $this->report;
            }
        };
    }
}
