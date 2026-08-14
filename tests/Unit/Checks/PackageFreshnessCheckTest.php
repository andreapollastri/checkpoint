<?php

namespace Checkpoint\Tests\Unit\Checks;

use Checkpoint\Checks\CheckResult;
use Checkpoint\Checks\PackageFreshnessCheck;
use Checkpoint\Tests\TestCase;

class PackageFreshnessCheckTest extends TestCase
{
    public function test_warns_when_composer_lock_is_missing(): void
    {
        $workspace = $this->makeWorkspace();

        $result = (new PackageFreshnessCheck($workspace))->run();

        $this->assertSame(CheckResult::WARN, $result->status);
        $this->assertStringContainsString('composer.lock not found', $result->message);
    }

    public function test_passes_when_all_packages_are_older_than_the_threshold(): void
    {
        $workspace = $this->makeWorkspace();
        $this->writeComposerLock($workspace, [
            ['name' => 'acme/old-pkg', 'version' => '1.0.0', 'releasedAt' => time() - (10 * 86400)],
        ]);

        $result = (new PackageFreshnessCheck($workspace, 3))->run();

        $this->assertSame(CheckResult::PASS, $result->status);
        $this->assertSame([], $result->details);
    }

    public function test_fails_when_a_package_was_released_within_the_threshold(): void
    {
        $workspace = $this->makeWorkspace();
        $this->writeComposerLock($workspace, [
            ['name' => 'acme/fresh-pkg', 'version' => '1.2.3', 'releasedAt' => time() - 3600],
        ]);

        $result = (new PackageFreshnessCheck($workspace, 3))->run();

        $this->assertSame(CheckResult::FAIL, $result->status);
        $this->assertCount(1, $result->details);
        $this->assertMatchesRegularExpression(
            '/^acme\/fresh-pkg 1\.2\.3 released \d+h ago$/',
            $result->details[0],
        );
    }

    public function test_suppression_hash_is_based_on_package_name_and_version_only(): void
    {
        $workspace = $this->makeWorkspace();
        $this->writeComposerLock($workspace, [
            ['name' => 'acme/fresh-pkg', 'version' => '1.2.3', 'releasedAt' => time() - 3600],
        ]);

        $result = (new PackageFreshnessCheck($workspace, 3))->run();
        $detail = $result->details[0];
        $stable = CheckResult::hashFinding(
            'Package Freshness (Supply Chain)',
            'acme/fresh-pkg 1.2.3',
        );
        $ageDependent = CheckResult::hashFinding(
            'Package Freshness (Supply Chain)',
            $detail,
        );

        $this->assertSame($stable, $result->hashes[$detail]);
        $this->assertSame($stable, $result->hashFor('Package Freshness (Supply Chain)', $detail));
        $this->assertNotSame($ageDependent, $result->hashes[$detail]);
    }

    public function test_suppression_hash_does_not_change_when_the_release_ages_by_an_hour(): void
    {
        $checkName = 'Package Freshness (Supply Chain)';
        $workspace = $this->makeWorkspace();

        $this->writeComposerLock($workspace, [
            ['name' => 'acme/fresh-pkg', 'version' => '1.2.3', 'releasedAt' => time() - (5 * 3600)],
        ]);
        $newer = (new PackageFreshnessCheck($workspace, 3))->run();

        $this->writeComposerLock($workspace, [
            ['name' => 'acme/fresh-pkg', 'version' => '1.2.3', 'releasedAt' => time() - (6 * 3600)],
        ]);
        $older = (new PackageFreshnessCheck($workspace, 3))->run();

        $this->assertStringContainsString('released 5h ago', $newer->details[0]);
        $this->assertStringContainsString('released 6h ago', $older->details[0]);
        $this->assertNotSame($newer->details[0], $older->details[0]);
        $this->assertSame(
            $newer->hashFor($checkName, $newer->details[0]),
            $older->hashFor($checkName, $older->details[0]),
        );
    }

    public function test_skips_whitelisted_package_names(): void
    {
        $workspace = $this->makeWorkspace();
        $this->writeComposerLock($workspace, [
            ['name' => 'acme/fresh-pkg', 'version' => '1.2.3', 'releasedAt' => time() - 3600],
        ]);

        $result = (new PackageFreshnessCheck($workspace, 3, ['acme/fresh-pkg']))->run();

        $this->assertSame(CheckResult::PASS, $result->status);
        $this->assertStringContainsString('1 whitelisted package(s) skipped', $result->message);
    }

    /**
     * @param  list<array{name: string, version: string, releasedAt: int}>  $packages
     */
    private function writeComposerLock(string $workspace, array $packages): void
    {
        $encoded = array_map(fn (array $package) => [
            'name' => $package['name'],
            'version' => $package['version'],
            'time' => gmdate('Y-m-d\TH:i:s+00:00', $package['releasedAt']),
        ], $packages);

        $this->writeFile($workspace, 'composer.lock', json_encode([
            'packages' => $encoded,
            'packages-dev' => [],
        ], JSON_THROW_ON_ERROR));
    }
}
