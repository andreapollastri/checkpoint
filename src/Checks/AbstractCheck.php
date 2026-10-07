<?php

namespace Checkpoint\Checks;

abstract class AbstractCheck
{
    /** Composer stderr lines that are not the reason a command failed. */
    protected const COMPOSER_NOISE = ['Composer could not detect the root package'];

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

    /**
     * First meaningful line of a tool's output (e.g. stderr of a failed
     * `composer` / `npm` run), trimmed for display in finding details.
     *
     * @param  string[]  $ignorePrefixes  Noise lines to skip.
     */
    public static function firstLine(string $output, array $ignorePrefixes = []): string
    {
        foreach (preg_split('/\R/', $output) ?: [] as $line) {
            $line = trim($line);

            if ($line === '') {
                continue;
            }

            foreach ($ignorePrefixes as $prefix) {
                if (str_starts_with($line, $prefix)) {
                    continue 2;
                }
            }

            return mb_strimwidth($line, 0, 200, '…');
        }

        return '';
    }
}
