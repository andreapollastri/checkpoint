<?php

namespace Checkpoint\Checks;

abstract class AbstractCheck
{
    abstract public function name(): string;

    abstract public function run(): CheckResult;

    /**
     * Strip $basePath as a leading prefix only.
     *
     * Unlike str_replace(), this does not remove later occurrences of the same
     * substring (e.g. basePath "/app" must not strip the "app/" directory).
     */
    public static function relativePath(string $basePath, string $absolutePath): string
    {
        $relative = preg_replace('#^'.preg_quote($basePath, '#').'#', '', $absolutePath);

        return ltrim((string) $relative, '/');
    }
}
