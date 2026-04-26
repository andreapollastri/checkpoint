<?php

namespace Checkpoint\Checks;

use Symfony\Component\Finder\Finder;

class DebugFunctionsCheck extends AbstractCheck
{
    private const DEBUG_FUNCTIONS = [
        'var_dump', 'print_r', 'var_export', 'dd', 'dump', 'ray', 'rdump',
    ];

    private const EXCLUDE_PATHS = [
        'vendor',
        'node_modules',
        'storage',
        'bootstrap/cache',
        '.git',
        'tests',
    ];

    public function __construct(private readonly string $basePath) {}

    public function name(): string
    {
        return 'Debug Functions in Production Code';
    }

    public function run(): CheckResult
    {
        $finder = new Finder();
        $finder->files()
            ->in($this->basePath)
            ->name('*.php')
            ->notPath(self::EXCLUDE_PATHS);

        $findings = [];
        $fnPattern = implode('|', self::DEBUG_FUNCTIONS);
        $pattern = '/\b(?:'.$fnPattern.')\s*\(/';

        foreach ($finder as $file) {
            $lines = explode("\n", $file->getContents());
            $relative = ltrim(str_replace($this->basePath, '', $file->getRealPath()), '/');

            foreach ($lines as $i => $line) {
                $trimmed = trim($line);
                if (str_starts_with($trimmed, '//') || str_starts_with($trimmed, '*')) {
                    continue;
                }
                if (preg_match($pattern, $line)) {
                    $findings[] = "{$relative}:".($i + 1).' — '.mb_strimwidth($trimmed, 0, 100, '…');
                }
            }
        }

        if (empty($findings)) {
            return CheckResult::pass('No debug functions found in production code.');
        }

        return CheckResult::warn(count($findings).' debug function call(s) found outside of tests.', $findings);
    }
}
