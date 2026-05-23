<?php

namespace Checkpoint\Checks;

use Symfony\Component\Finder\Finder;

class WeakCryptographyCheck extends AbstractCheck
{
    private const EXCLUDE_PATHS = [
        'vendor',
        'node_modules',
        'storage',
        'bootstrap/cache',
        '.git',
        'tests',
    ];

    private const SECURITY_KEYWORDS = 'password|secret|token|signature|hmac|api_?key|auth|verify|salt';

    public function __construct(private readonly string $basePath) {}

    public function name(): string
    {
        return 'Weak Cryptography';
    }

    public function run(): CheckResult
    {
        $finder = new Finder();
        $finder->files()
            ->in($this->basePath)
            ->name('*.php')
            ->notPath(self::EXCLUDE_PATHS);

        $findings = [];
        $hasCritical = false;

        foreach ($finder as $file) {
            $lines = explode("\n", $file->getContents());
            $relative = ltrim(str_replace($this->basePath, '', $file->getRealPath()), '/');

            foreach ($lines as $i => $line) {
                $trimmed = trim($line);
                $location = "{$relative}:".($i + 1);

                // mcrypt_* — entirely deprecated, no legitimate use
                if (preg_match('/\bmcrypt_[a-z_]+\s*\(/', $line)) {
                    $findings[] = "{$location} — mcrypt_* is deprecated and broken: ".mb_strimwidth($trimmed, 0, 120, '…');
                    $hasCritical = true;

                    continue;
                }

                // ECB cipher mode in openssl_encrypt / openssl_decrypt
                if (preg_match('/openssl_(?:encrypt|decrypt)\s*\([^)]*[\'"][^"\']*-ecb[\'"]/i', $line)) {
                    $findings[] = "{$location} — ECB cipher mode is insecure (use CBC/GCM): ".mb_strimwidth($trimmed, 0, 120, '…');
                    $hasCritical = true;

                    continue;
                }

                // DES cipher (always weak)
                if (preg_match('/[\'"](?:des|3des|rc4|rc2)(?:-[a-z0-9]+)?[\'"]/i', $line) && preg_match('/openssl_(?:encrypt|decrypt)/', $line)) {
                    $findings[] = "{$location} — DES/3DES/RC4 cipher is broken: ".mb_strimwidth($trimmed, 0, 120, '…');
                    $hasCritical = true;

                    continue;
                }

                // md5() / sha1() called near a security keyword in the line
                if (preg_match('/\b(md5|sha1)\s*\(/i', $line, $m)
                    && preg_match('/'.self::SECURITY_KEYWORDS.'/i', $line)) {
                    $findings[] = "{$location} — weak hash {$m[1]}() in a security context: ".mb_strimwidth($trimmed, 0, 120, '…');
                }
            }
        }

        if (empty($findings)) {
            return CheckResult::pass('No obvious weak-cryptography patterns detected.');
        }

        $count = count($findings);

        return $hasCritical
            ? CheckResult::fail("{$count} weak-cryptography issue(s) found.", $findings)
            : CheckResult::warn("{$count} weak-cryptography issue(s) found.", $findings);
    }
}
