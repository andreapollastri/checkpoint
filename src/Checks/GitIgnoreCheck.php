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
        'auth.json',
    ];

    /**
     * Files that must never be committed, with the follow-up to give when they are.
     */
    private const NEVER_TRACKED = [
        '.env' => 'remove it with `git rm --cached .env` immediately.',
        'auth.json' => 'it holds Composer registry credentials — remove it with `git rm --cached auth.json` and rotate the tokens.',
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

        // Check if secret files are tracked by git (the worst case)
        foreach (self::NEVER_TRACKED as $file => $advice) {
            if (! file_exists($this->basePath.'/'.$file)) {
                continue;
            }

            exec('git -C '.escapeshellarg($this->basePath).' ls-files --error-unmatch '.escapeshellarg($file).' 2>/dev/null', $out, $code);
            if ($code === 0) {
                return CheckResult::fail("{$file} is actively tracked by git — {$advice}");
            }
        }

        if (empty($missing)) {
            return CheckResult::pass('All expected sensitive patterns are excluded in .gitignore.');
        }

        return CheckResult::warn(count($missing).' pattern(s) missing from .gitignore.', $missing);
    }
}
