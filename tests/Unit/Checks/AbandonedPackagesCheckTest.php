<?php

namespace Checkpoint\Tests\Unit\Checks;

use Checkpoint\Checks\AbandonedPackagesCheck;
use Checkpoint\Checks\CheckResult;
use Checkpoint\Tests\TestCase;

class AbandonedPackagesCheckTest extends TestCase
{
    public function test_warns_when_composer_lock_is_missing(): void
    {
        $workspace = $this->makeWorkspace();

        $result = (new AbandonedPackagesCheck($workspace))->run();

        $this->assertSame(CheckResult::WARN, $result->status);
        $this->assertStringContainsString('composer.lock not found', $result->message);
    }

    public function test_passes_when_no_package_is_abandoned(): void
    {
        $workspace = $this->makeWorkspace();
        $this->writeLock($workspace, [
            ['name' => 'acme/maintained', 'version' => '1.0.0'],
            ['name' => 'acme/explicit', 'version' => '1.0.0', 'abandoned' => false],
        ]);

        $result = (new AbandonedPackagesCheck($workspace))->run();

        $this->assertSame(CheckResult::PASS, $result->status);
    }

    public function test_warns_with_suggested_replacement(): void
    {
        $workspace = $this->makeWorkspace();
        $this->writeLock($workspace, [
            ['name' => 'swiftmailer/swiftmailer', 'version' => '6.3.0', 'abandoned' => 'symfony/mailer'],
            ['name' => 'acme/orphan', 'version' => '0.1.0', 'abandoned' => true],
        ]);

        $result = (new AbandonedPackagesCheck($workspace))->run();

        $this->assertSame(CheckResult::WARN, $result->status);
        $this->assertSame([
            'swiftmailer/swiftmailer is abandoned — use symfony/mailer instead',
            'acme/orphan is abandoned — no replacement suggested',
        ], $result->details);
    }

    public function test_marks_dev_packages(): void
    {
        $workspace = $this->makeWorkspace();
        $this->writeLock($workspace, [], [
            ['name' => 'acme/dev-tool', 'version' => '1.0.0', 'abandoned' => true],
        ]);

        $result = (new AbandonedPackagesCheck($workspace))->run();

        $this->assertSame(['acme/dev-tool is abandoned — no replacement suggested [dev]'], $result->details);
    }

    /**
     * @param  list<array<string, mixed>>  $packages
     * @param  list<array<string, mixed>>  $devPackages
     */
    private function writeLock(string $workspace, array $packages, array $devPackages = []): void
    {
        $this->writeFile($workspace, 'composer.lock', json_encode([
            'packages' => $packages,
            'packages-dev' => $devPackages,
        ], JSON_THROW_ON_ERROR));
    }
}
