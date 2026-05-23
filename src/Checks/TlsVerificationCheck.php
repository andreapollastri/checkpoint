<?php

namespace Checkpoint\Checks;

use Symfony\Component\Finder\Finder;

class TlsVerificationCheck extends AbstractCheck
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
        return 'TLS Certificate Verification';
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
                // Laravel HTTP client: Http::withoutVerifying() or ->withoutVerifying()
                if (preg_match('/->withoutVerifying\s*\(/', $line) || preg_match('/\bHttp::withoutVerifying\s*\(/', $line)) {
                    $findings[] = "{$relative}:".($i + 1).' — Http::withoutVerifying() disables TLS verification: '.mb_strimwidth(trim($line), 0, 120, '…');
                    continue;
                }

                // Guzzle / array option: 'verify' => false
                if (preg_match('/["\']verify["\']\s*=>\s*false/', $line)) {
                    $findings[] = "{$relative}:".($i + 1).' — \'verify\' => false disables TLS verification: '.mb_strimwidth(trim($line), 0, 120, '…');
                    continue;
                }

                // curl_setopt CURLOPT_SSL_VERIFYPEER / VERIFYHOST set to false or 0
                if (preg_match('/CURLOPT_SSL_VERIFY(?:PEER|HOST)\s*,\s*(?:false|0)\b/i', $line)) {
                    $findings[] = "{$relative}:".($i + 1).' — CURLOPT_SSL_VERIFYPEER/HOST disabled: '.mb_strimwidth(trim($line), 0, 120, '…');
                    continue;
                }

                // stream_context: 'verify_peer' => false / 'verify_peer_name' => false / 'allow_self_signed' => true
                if (preg_match('/["\']verify_peer(?:_name)?["\']\s*=>\s*false/', $line)) {
                    $findings[] = "{$relative}:".($i + 1).' — verify_peer disabled in stream context: '.mb_strimwidth(trim($line), 0, 120, '…');
                    continue;
                }

                if (preg_match('/["\']allow_self_signed["\']\s*=>\s*true/', $line)) {
                    $findings[] = "{$relative}:".($i + 1).' — allow_self_signed enabled: '.mb_strimwidth(trim($line), 0, 120, '…');
                    continue;
                }
            }
        }

        if (empty($findings)) {
            return CheckResult::pass('No disabled TLS verification detected.');
        }

        return CheckResult::fail(count($findings).' TLS verification issue(s) found.', $findings);
    }
}
