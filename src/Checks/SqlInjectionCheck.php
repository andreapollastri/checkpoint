<?php

namespace Checkpoint\Checks;

use Symfony\Component\Finder\Finder;

class SqlInjectionCheck extends AbstractCheck
{
    // Raw query patterns where a PHP variable appears directly inside the SQL string
    private const PATTERNS = [
        // DB::select/insert/update/delete/statement("... $var ...")
        '/DB::\w+\s*\(\s*(?:"[^"]*\$[a-z_\[\'"]|\'[^\']*\$[a-z_\[\'"]])/i',
        // ->whereRaw("... $var ...")
        '/->whereRaw\s*\(\s*(?:"[^"]*\$[a-z_\[\'"]|\'[^\']*\$[a-z_\[\'"]])/i',
        // ->selectRaw / ->orderByRaw / ->havingRaw / ->groupByRaw
        '/->(?:select|orderBy|having|groupBy|from)Raw\s*\(\s*(?:"[^"]*\$[a-z_\[\'"]|\'[^\']*\$[a-z_\[\'"]])/i',
        // DB::raw("... $var ...")
        '/DB::raw\s*\(\s*(?:"[^"]*\$[a-z_\[\'"]|\'[^\']*\$[a-z_\[\'"]])/i',
        // String concatenation inside raw query: "SELECT " . $var
        '/DB::\w+\s*\(\s*["\'][^"\']*["\']\s*\.\s*\$/',
        // sprintf("SELECT ... %s", $var) style
        '/sprintf\s*\(\s*["\'](?:SELECT|INSERT|UPDATE|DELETE|CREATE|DROP|ALTER)\b/i',
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
        return 'SQL Injection Risks';
    }

    public function run(): CheckResult
    {
        $finder = new Finder;
        $finder->files()
            ->in($this->basePath)
            ->name('*.php')
            ->notPath(self::EXCLUDE_PATHS);

        $findings = [];

        foreach ($finder as $file) {
            $lines = explode("\n", $file->getContents());
            $relative = ltrim(str_replace($this->basePath, '', $file->getRealPath()), '/');

            foreach ($lines as $i => $line) {
                foreach (self::PATTERNS as $pattern) {
                    if (preg_match($pattern, $line)) {
                        $findings[] = "{$relative}:".($i + 1).' — '.mb_strimwidth(trim($line), 0, 120, '…');
                        break;
                    }
                }
            }
        }

        if (empty($findings)) {
            return CheckResult::pass('No obvious SQL injection risks detected.');
        }

        return CheckResult::fail(count($findings).' potential SQL injection risk(s) found.', $findings);
    }
}
