<?php

namespace Checkpoint\Checks;

use Checkpoint\ScanPaths;
use Symfony\Component\Finder\Finder;

class XssCheck extends AbstractCheck
{
    // Variables that are always safe to output unescaped in Blade
    private const SAFE_UNESCAPED_VARS = ['slot', 'loop', '__env', 'errors'];

    public function __construct(private readonly string $basePath) {}

    public function name(): string
    {
        return 'XSS (Cross-Site Scripting) Risks';
    }

    public function run(): CheckResult
    {
        $findings = [];

        $viewsPath = $this->basePath.'/resources/views';

        if (! is_dir($viewsPath)) {
            return CheckResult::warn('resources/views/ not found — skipping XSS check.');
        }

        $finder = new Finder();
        $finder->files()
            ->in($viewsPath)
            ->name('*.blade.php');

        foreach ($finder as $file) {
            $lines = explode("\n", $file->getContents());
            $relative = ltrim(str_replace($this->basePath, '', $file->getRealPath()), '/');

            foreach ($lines as $i => $line) {
                // {!! $variable !!} — unescaped output
                if (preg_match('/\{!!\s*\$(\w+)/', $line, $m)) {
                    if (! in_array($m[1], self::SAFE_UNESCAPED_VARS, true)) {
                        $findings[] = "{$relative}:".($i + 1).' — Unescaped output: '.mb_strimwidth(trim($line), 0, 100, '…');
                    }
                }
            }
        }

        // Also check PHP files for raw echo of request data
        $phpFinder = ScanPaths::configure(new Finder());
        $phpFinder->files()
            ->in($this->basePath)
            ->name('*.php');

        foreach ($phpFinder as $file) {
            $lines = explode("\n", $file->getContents());
            $relative = ltrim(str_replace($this->basePath, '', $file->getRealPath()), '/');

            foreach ($lines as $i => $line) {
                // echo $request->input(...) without e() or htmlspecialchars()
                if (preg_match('/\becho\b.+\brequest\b.+(?:input|get|post|query)\s*\(/i', $line)
                    && ! preg_match('/htmlspecialchars|htmlentities|\be\(/', $line)) {
                    $findings[] = "{$relative}:".($i + 1).' — Unescaped echo of request data: '.mb_strimwidth(trim($line), 0, 100, '…');
                }
            }
        }

        if (empty($findings)) {
            return CheckResult::pass('No obvious XSS risks detected.');
        }

        return CheckResult::warn(count($findings).' potential XSS risk(s) found.', $findings);
    }
}
