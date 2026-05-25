<?php

namespace Checkpoint\Checks;

use Symfony\Component\Finder\Finder;

class CommandInjectionCheck extends AbstractCheck
{
    private const DANGEROUS_FUNCTIONS = [
        'exec', 'shell_exec', 'system', 'passthru', 'proc_open', 'popen',
    ];

    private const EXCLUDE_PATHS = [
        'vendor',
        'node_modules',
        'storage',
        'bootstrap/cache',
        '.git',
    ];

    public function __construct(private readonly string $basePath) {}

    public function name(): string
    {
        return 'Command Injection Risks';
    }

    public function run(): CheckResult
    {
        $finder = new Finder;
        $finder->files()
            ->in($this->basePath)
            ->name('*.php')
            ->notPath(self::EXCLUDE_PATHS);

        $findings = [];

        $fnPattern = implode('|', self::DANGEROUS_FUNCTIONS);
        // Match calls where a variable is passed directly (not through escapeshellarg/cmd)
        $pattern = '/\b(?:'.$fnPattern.')\s*\([^)]*\$(?!this)[a-zA-Z_]/';

        foreach ($finder as $file) {
            $lines = explode("\n", $file->getContents());
            $relative = ltrim(str_replace($this->basePath, '', $file->getRealPath()), '/');

            foreach ($lines as $i => $line) {
                if (! preg_match($pattern, $line)) {
                    continue;
                }
                // Exclude lines that do properly escape
                if (preg_match('/escapeshellarg|escapeshellcmd/', $line)) {
                    continue;
                }
                $findings[] = "{$relative}:".($i + 1).' — '.mb_strimwidth(trim($line), 0, 120, '…');
            }
        }

        if (empty($findings)) {
            return CheckResult::pass('No obvious command injection risks detected.');
        }

        return CheckResult::fail(count($findings).' potential command injection risk(s) found.', $findings);
    }
}
