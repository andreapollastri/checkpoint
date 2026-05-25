<?php

namespace Checkpoint\Checks;

use Symfony\Component\Finder\Finder;

class InsecureRngCheck extends AbstractCheck
{
    private const EXCLUDE_PATHS = [
        'vendor',
        'node_modules',
        'storage',
        'bootstrap/cache',
        '.git',
        'tests',
    ];

    private const SECURITY_KEYWORDS = 'token|secret|reset|csrf|nonce|salt|password|verifier|api_?key|otp|2fa|confirmation';

    public function __construct(private readonly string $basePath) {}

    public function name(): string
    {
        return 'Insecure RNG';
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
                // rand() / mt_rand() / uniqid() called on the same line as a security keyword
                if (preg_match('/\b(rand|mt_rand|uniqid)\s*\(/', $line, $m)
                    && preg_match('/'.self::SECURITY_KEYWORDS.'/i', $line)) {
                    $findings[] = "{$relative}:".($i + 1).' — '.$m[1].'() used for a secret/token (use random_bytes / Str::random): '.mb_strimwidth(trim($line), 0, 120, '…');
                }
            }
        }

        if (empty($findings)) {
            return CheckResult::pass('No insecure RNG usage detected in security contexts.');
        }

        return CheckResult::fail(count($findings).' insecure RNG usage(s) found in security contexts.', $findings);
    }
}
