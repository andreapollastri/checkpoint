<?php

namespace Checkpoint\Tests\Concerns;

use FilesystemIterator;
use RecursiveDirectoryIterator;
use RecursiveIteratorIterator;

/**
 * Creates throwaway temporary directories that mimic a Laravel project
 * tree, so checks can scan real files without touching the host project.
 */
trait CreatesWorkspace
{
    /** @var string[] */
    private array $workspaces = [];

    /**
     * Create a fresh, isolated temp directory and return its real path.
     */
    protected function makeWorkspace(): string
    {
        $path = sys_get_temp_dir().'/checkpoint-test-'.bin2hex(random_bytes(8));

        if (! mkdir($path, 0777, true) && ! is_dir($path)) {
            $this->fail("Unable to create workspace at {$path}");
        }

        // realpath() resolves symlinks (e.g. macOS /var -> /private/var) so that
        // the base path matches the file paths produced by Symfony Finder.
        $real = realpath($path) ?: $path;
        $this->workspaces[] = $real;

        return $real;
    }

    /**
     * Write a file (creating parent directories) inside a workspace.
     */
    protected function writeFile(string $base, string $relative, string $contents): string
    {
        $full = rtrim($base, '/').'/'.ltrim($relative, '/');
        $dir = dirname($full);

        if (! is_dir($dir)) {
            mkdir($dir, 0777, true);
        }

        file_put_contents($full, $contents);

        return $full;
    }

    protected function cleanWorkspaces(): void
    {
        foreach ($this->workspaces as $workspace) {
            $this->deleteRecursively($workspace);
        }

        $this->workspaces = [];
    }

    private function deleteRecursively(string $path): void
    {
        if (! file_exists($path)) {
            return;
        }

        if (! is_dir($path)) {
            @unlink($path);

            return;
        }

        $items = new RecursiveIteratorIterator(
            new RecursiveDirectoryIterator($path, FilesystemIterator::SKIP_DOTS),
            RecursiveIteratorIterator::CHILD_FIRST,
        );

        foreach ($items as $item) {
            if ($item->isDir()) {
                @rmdir($item->getPathname());
            } else {
                @unlink($item->getPathname());
            }
        }

        @rmdir($path);
    }
}
