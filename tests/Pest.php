<?php

use Checkpoint\Tests\TestCase;

uses(TestCase::class)->in(__DIR__);

afterEach(fn () => checkpointCleanup());

/**
 * Build a throwaway project dir (path => contents), cleaned up after each test.
 */
function tempProject(array $files = []): string
{
    $base = sys_get_temp_dir().'/checkpoint-test-'.uniqid('', true);
    mkdir($base, 0777, true);

    foreach ($files as $path => $contents) {
        $full = $base.'/'.ltrim($path, '/');
        $dir = dirname($full);

        if (! is_dir($dir)) {
            mkdir($dir, 0777, true);
        }

        file_put_contents($full, $contents);
    }

    checkpointCleanup($base);

    return $base;
}

function checkpointCleanup(?string $register = null): void
{
    static $dirs = [];

    if ($register !== null) {
        $dirs[] = $register;

        return;
    }

    foreach ($dirs as $dir) {
        checkpointRemoveDir($dir);
    }

    $dirs = [];
}

function checkpointRemoveDir(string $dir): void
{
    if (! is_dir($dir)) {
        return;
    }

    $items = new RecursiveIteratorIterator(
        new RecursiveDirectoryIterator($dir, FilesystemIterator::SKIP_DOTS),
        RecursiveIteratorIterator::CHILD_FIRST
    );

    foreach ($items as $item) {
        $item->isDir() ? rmdir($item->getPathname()) : unlink($item->getPathname());
    }

    rmdir($dir);
}
