<?php

namespace Checkpoint\Checks;

use Symfony\Component\Finder\Finder;

class OpenRedirectCheck extends AbstractCheck
{
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
        return 'Open Redirect Risks';
    }

    public function run(): CheckResult
    {
        $finder = new Finder();
        $finder->files()
            ->in($this->basePath)
            ->name('*.php')
            ->notPath(self::EXCLUDE_PATHS);

        $findings = [];

        foreach ($finder as $file) {
            $lines = explode("\n", $file->getContents());
            $relative = ltrim(str_replace($this->basePath, '', $file->getRealPath()), '/');

            foreach ($lines as $i => $line) {
                // redirect($request->...) or redirect($input) directly
                if (preg_match('/\bredirect\s*\(\s*\$(?:request|_GET|_POST|_REQUEST|input)\b/', $line)) {
                    $findings[] = "{$relative}:".($i + 1).' — redirect() with unvalidated input: '.mb_strimwidth(trim($line), 0, 100, '…');
                }

                // redirect()->to($userControlledVar)
                if (preg_match('/->to\s*\(\s*\$(?:request|_GET|_POST|_REQUEST|input)\b/', $line)) {
                    $findings[] = "{$relative}:".($i + 1).' — redirect()->to() with unvalidated input: '.mb_strimwidth(trim($line), 0, 100, '…');
                }

                // header('Location: ' . $var)
                if (preg_match('/header\s*\(\s*["\']Location:\s*["\']\s*\.\s*\$/', $line)) {
                    $findings[] = "{$relative}:".($i + 1).' — header(Location:) with dynamic value: '.mb_strimwidth(trim($line), 0, 100, '…');
                }
            }
        }

        if (empty($findings)) {
            return CheckResult::pass('No obvious open redirect risks detected.');
        }

        return CheckResult::warn(count($findings).' potential open redirect(s) found.', $findings);
    }
}
