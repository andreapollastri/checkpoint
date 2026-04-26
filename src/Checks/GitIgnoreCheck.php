<?php

namespace Checkpoint\Checks;

class GitIgnoreCheck extends AbstractCheck
{
    private const REQUIRED_PATTERNS = [
        '.env',
        '*.key',
        '*.pem',
        'storage/logs',
        '.env.backup',
        '.env.production',
    ];

    public function __construct(private readonly string $basePath) {}

    public function name(): string
    {
        return '.gitignore Sensitive Files';
    }

    public function run(): CheckResult
    {
        $gitignorePath = $this->basePath.'/.gitignore';

        if (! file_exists($gitignorePath)) {
            return CheckResult::fail('.gitignore not found — sensitive files may be committed to version control.');
        }

        $content = file_get_contents($gitignorePath);
        $missing = [];

        foreach (self::REQUIRED_PATTERNS as $pattern) {
            if (! str_contains($content, $pattern)) {
                $missing[] = "\"{$pattern}\" is not listed in .gitignore.";
            }
        }

        // Check if .env is tracked by git (the worst case)
        $envPath = $this->basePath.'/.env';
        if (file_exists($envPath)) {
            exec('git -C '.escapeshellarg($this->basePath).' ls-files --error-unmatch .env 2>/dev/null', $out, $code);
            if ($code === 0) {
                return CheckResult::fail('.env is actively tracked by git — remove it with `git rm --cached .env` immediately.');
            }
        }

        if (empty($missing)) {
            return CheckResult::pass('All expected sensitive patterns are excluded in .gitignore.');
        }

        return CheckResult::warn(count($missing).' pattern(s) missing from .gitignore.', $missing);
    }
}
