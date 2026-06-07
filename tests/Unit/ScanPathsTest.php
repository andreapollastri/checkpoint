<?php

namespace Checkpoint\Tests\Unit;

use Checkpoint\ScanPaths;
use Checkpoint\Tests\TestCase;

class ScanPathsTest extends TestCase
{
    public function test_merge_includes_built_in_defaults(): void
    {
        config()->set('checkpoint.exclude_paths', []);

        $paths = ScanPaths::merge(ScanPaths::DEFAULT);

        $this->assertContains('vendor', $paths);
        $this->assertContains('node_modules', $paths);
        $this->assertContains('storage', $paths);
    }

    public function test_merge_adds_configured_paths(): void
    {
        config()->set('checkpoint.exclude_paths', [
            'storage/app/mounted-data',
            '/data/external/',
        ]);

        $paths = ScanPaths::merge(ScanPaths::DEFAULT);

        $this->assertContains('storage/app/mounted-data', $paths);
        $this->assertContains('data/external', $paths);
    }

    public function test_merge_deduplicates_paths(): void
    {
        config()->set('checkpoint.exclude_paths', ['vendor', 'custom']);

        $paths = ScanPaths::merge(ScanPaths::DEFAULT);

        $this->assertSame(1, count(array_filter($paths, static fn (string $path): bool => $path === 'vendor')));
        $this->assertContains('custom', $paths);
    }
}
