<?php

namespace Checkpoint\Checks;

use Checkpoint\ScanPaths;
use Symfony\Component\Finder\Finder;

class InsecureDeserializationCheck extends AbstractCheck
{
    public function __construct(private readonly string $basePath) {}

    public function name(): string
    {
        return 'Insecure Deserialization';
    }

    public function run(): CheckResult
    {
        $finder = ScanPaths::configure(new Finder());
        $finder->files()
            ->in($this->basePath)
            ->name('*.php');

        $findings = [];

        foreach ($finder as $file) {
            $lines = explode("\n", $file->getContents());
            $relative = ltrim(str_replace($this->basePath, '', $file->getRealPath()), '/');

            foreach ($lines as $i => $line) {
                // unserialize() with a variable argument that is not a fixed internal value
                if (preg_match('/\bunserialize\s*\(\s*\$(?!this)[a-zA-Z_]/', $line)) {
                    if ($this->usesAllowedClassesRestriction($line)) {
                        continue;
                    }

                    $findings[] = "{$relative}:".($i + 1).' — unserialize() with dynamic input: '.mb_strimwidth(trim($line), 0, 100, '…');
                }

                // base64_decode + unserialize combo (common exploit chain)
                if (preg_match('/unserialize\s*\(\s*base64_decode/', $line)) {
                    $findings[] = "{$relative}:".($i + 1).' — unserialize(base64_decode(...)) detected (common exploit chain).';
                }
            }
        }

        if (empty($findings)) {
            return CheckResult::pass('No insecure deserialization patterns detected.');
        }

        return CheckResult::fail(count($findings).' insecure deserialization risk(s) found.', $findings);
    }

    private function usesAllowedClassesRestriction(string $line): bool
    {
        return (bool) preg_match('/allowed_classes["\']?\s*=>/i', $line);
    }
}
