<?php

namespace Checkpoint\Checks;

use Symfony\Component\Finder\Finder;

class CompromisedDependencyCheck extends AbstractCheck
{
    /**
     * Known supply-chain compromises. A finding is raised only when EVERY marker
     * of a signature appears in the same vendor file, so a legitimately named
     * package (for example a real "flipboxstudio" vendor) does not trip the check.
     *
     * @var array<string, array{description: string, markers: string[]}>
     */
    private const SIGNATURES = [
        'laravel-lang / flipbox (May 2026)' => [
            'description' => 'Obfuscated payload that exfiltrates to flipboxstudio, injected into a package helpers.php loaded via composer autoload.files.',
            'markers' => ['flipboxstudio', 'chr(', 'file_get_contents'],
        ],
    ];

    public function __construct(private readonly string $basePath) {}

    public function name(): string
    {
        return 'Compromised Dependencies';
    }

    public function run(): CheckResult
    {
        $vendorPath = $this->basePath.'/vendor';

        if (! is_dir($vendorPath)) {
            return CheckResult::pass('No vendor/ directory present — nothing to scan for known compromises.');
        }

        // The known attacks inject their payload into an autoloaded helpers.php.
        $finder = new Finder;
        $finder->files()
            ->in($vendorPath)
            ->name('helpers.php');

        $findings = [];

        foreach ($finder as $file) {
            $contents = $file->getContents();
            $relative = ltrim(str_replace($this->basePath, '', $file->getRealPath()), '/');

            foreach (self::SIGNATURES as $name => $signature) {
                if ($this->matchesEveryMarker($contents, $signature['markers'])) {
                    $findings[] = "{$relative} matches known compromise \"{$name}\": {$signature['description']}";
                }
            }
        }

        if (empty($findings)) {
            return CheckResult::pass('No known compromised-dependency signatures detected in vendor/.');
        }

        return CheckResult::fail(
            count($findings).' known compromised dependency signature(s) detected — remove the package, restore a clean version, and rotate any exposed secrets immediately.',
            $findings
        );
    }

    /**
     * @param  string[]  $markers
     */
    private function matchesEveryMarker(string $contents, array $markers): bool
    {
        foreach ($markers as $marker) {
            if (! str_contains($contents, $marker)) {
                return false;
            }
        }

        return true;
    }
}
