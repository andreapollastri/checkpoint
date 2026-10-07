<?php

namespace Checkpoint\Checks;

use Checkpoint\ScanPaths;
use Symfony\Component\Finder\Finder;

class XxeCheck extends AbstractCheck
{
    /**
     * libxml ≥ 2.9 (every PHP 8 build) does not expand external entities by
     * default, so XXE only happens when code opts back in. Each pattern below
     * is such an opt-in.
     */
    private const PATTERNS = [
        '/\bLIBXML_NOENT\b/' => 'LIBXML_NOENT substitutes entities (enables XXE on untrusted XML)',
        '/\bLIBXML_DTD(?:LOAD|ATTR)\b/' => 'LIBXML_DTDLOAD/DTDATTR loads external DTDs',
        '/\blibxml_disable_entity_loader\s*\(\s*false\b/i' => 'libxml_disable_entity_loader(false) re-enables the external entity loader',
        '/->substituteEntities\s*=\s*true\b/i' => 'DOMDocument::$substituteEntities = true expands entities',
        '/->resolveExternals\s*=\s*true\b/i' => 'DOMDocument::$resolveExternals = true loads external DTDs',
        '/XMLReader::(?:SUBST_ENTITIES|LOADDTD|DEFAULTATTRS)\s*,\s*true\b/i' => 'XMLReader parser property enables entity substitution / DTD loading',
    ];

    public function __construct(private readonly string $basePath) {}

    public function name(): string
    {
        return 'XML External Entity (XXE) Risks';
    }

    public function run(): CheckResult
    {
        $finder = ScanPaths::configure(new Finder(), ScanPaths::WITH_TESTS);
        $finder->files()
            ->in($this->basePath)
            ->name('*.php');

        $findings = [];

        foreach ($finder as $file) {
            $lines = explode("\n", $file->getContents());
            $relative = self::relativePath($this->basePath, (string) $file->getRealPath());

            foreach ($lines as $i => $line) {
                $trimmed = trim($line);
                if (str_starts_with($trimmed, '//') || str_starts_with($trimmed, '*') || str_starts_with($trimmed, '#')) {
                    continue;
                }

                foreach (self::PATTERNS as $pattern => $reason) {
                    if (preg_match($pattern, $line)) {
                        $findings[] = "{$relative}:".($i + 1)." — {$reason}: ".mb_strimwidth($trimmed, 0, 100, '…');
                        break;
                    }
                }
            }
        }

        if (empty($findings)) {
            return CheckResult::pass('No XML parser options that enable external entities detected.');
        }

        return CheckResult::fail(count($findings).' XXE risk(s) found — only enable entity/DTD loading for fully trusted XML.', $findings);
    }
}
