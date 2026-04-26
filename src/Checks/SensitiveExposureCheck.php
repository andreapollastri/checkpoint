<?php

namespace Checkpoint\Checks;

use Symfony\Component\Finder\Finder;

class SensitiveExposureCheck extends AbstractCheck
{
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
        return 'Sensitive Data Exposure';
    }

    public function run(): CheckResult
    {
        $findings = [];

        // Check that error reporting is suppressed
        $finder = new Finder();
        $finder->files()
            ->in($this->basePath)
            ->name('*.php')
            ->notPath(self::EXCLUDE_PATHS);

        foreach ($finder as $file) {
            $lines = explode("\n", $file->getContents());
            $relative = ltrim(str_replace($this->basePath, '', $file->getRealPath()), '/');

            foreach ($lines as $i => $line) {
                // error_reporting(E_ALL) in production paths
                if (preg_match('/\berror_reporting\s*\(\s*E_ALL\s*\)/', $line)) {
                    $findings[] = "{$relative}:".($i + 1).' — error_reporting(E_ALL) may expose internals.';
                }

                // ini_set('display_errors', 1 or 'On')
                if (preg_match('/ini_set\s*\(\s*["\']display_errors["\']\s*,\s*(?:["\']On["\']|1)\s*\)/i', $line)) {
                    $findings[] = "{$relative}:".($i + 1).' — display_errors is enabled.';
                }

                // Log::debug/info with request/password data
                if (preg_match('/Log::(?:debug|info)\s*\(.+\$(?:password|secret|token|key)\b/i', $line)) {
                    $findings[] = "{$relative}:".($i + 1).' — Logging potentially sensitive value: '.mb_strimwidth(trim($line), 0, 100, '…');
                }
            }
        }

        // Check that telescope/debugbar are not enabled in production (config check)
        $telescopeConfig = $this->basePath.'/config/telescope.php';
        if (file_exists($telescopeConfig)) {
            $content = file_get_contents($telescopeConfig);
            if (preg_match("/'enabled'\s*=>\s*true/", $content)) {
                $findings[] = 'config/telescope.php: Telescope is always enabled — guard with env(\'APP_ENV\') === \'local\'.';
            }
        }

        if (empty($findings)) {
            return CheckResult::pass('No obvious sensitive data exposure issues found.');
        }

        return CheckResult::warn(count($findings).' sensitive exposure issue(s) found.', $findings);
    }
}
