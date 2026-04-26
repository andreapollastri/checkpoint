<?php

namespace Checkpoint\Checks;

use Symfony\Component\Finder\Finder;

class HardcodedSecretsCheck extends AbstractCheck
{
    // Matches assignment of secret-sounding keys to literal string values
    private const PATTERNS = [
        // Array key => 'literal value'  or  ->method('literal')  for secret-named keys
        '/["\'](?:password|passwd|pwd|secret|api_key|apikey|api_secret|token|auth_token|access_token|private_key|client_secret|app_secret|webhook_secret)["\']\s*=>\s*["\'][^"\']{4,}["\']/i',
        // $variable = 'literal' where variable name looks like a secret
        '/\$(?:password|secret|api_key|apikey|token|access_token|private_key|client_secret)\s*=\s*["\'][^"\']{4,}["\']/i',
        // AWS access keys
        '/AKIA[0-9A-Z]{16}/',
        // PEM private key headers in source code
        '/-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----/',
        // Stripe live/test secret keys
        '/sk_(?:live|test)_[0-9a-zA-Z]{24,}/',
        // Generic Bearer tokens assigned literally
        '/["\']Bearer\s+[A-Za-z0-9\-._~+\/]{20,}["\']/',
        // GitHub personal access tokens
        '/ghp_[A-Za-z0-9]{36}/',
        // Slack tokens
        '/xox[baprs]-[0-9A-Za-z\-]{10,}/',
    ];

    private const EXCLUDE_PATHS = [
        'vendor',
        'node_modules',
        'storage',
        'bootstrap/cache',
        '.git',
        'tests',
    ];

    private const SAFE_FUNCTIONS = [
        'env(',
        'config(',
        'getenv(',
    ];

    public function __construct(private readonly string $basePath) {}

    public function name(): string
    {
        return 'Hardcoded Secrets';
    }

    public function run(): CheckResult
    {
        $finder = new Finder();
        $finder->files()
            ->in($this->basePath)
            ->name(['*.php', '*.js', '*.ts', '.env.example'])
            ->notPath(self::EXCLUDE_PATHS)
            ->notName('.env');

        $findings = [];

        foreach ($finder as $file) {
            $lines = explode("\n", $file->getContents());
            $relative = ltrim(str_replace($this->basePath, '', $file->getRealPath()), '/');

            foreach ($lines as $i => $line) {
                $trimmed = trim($line);

                if ($trimmed === '' || str_starts_with($trimmed, '//') || str_starts_with($trimmed, '#')) {
                    continue;
                }

                foreach (self::PATTERNS as $pattern) {
                    if (! preg_match($pattern, $line)) {
                        continue;
                    }

                    // Skip lines that fetch the value from env/config at runtime
                    $isSafe = false;
                    foreach (self::SAFE_FUNCTIONS as $fn) {
                        if (str_contains($line, $fn)) {
                            $isSafe = true;
                            break;
                        }
                    }

                    if (! $isSafe) {
                        $findings[] = "{$relative}:".($i + 1).' — '.mb_strimwidth($trimmed, 0, 120, '…');
                        break;
                    }
                }
            }
        }

        if (empty($findings)) {
            return CheckResult::pass('No hardcoded secrets detected.');
        }

        return CheckResult::fail(count($findings).' potential hardcoded secret(s) found.', $findings);
    }
}
