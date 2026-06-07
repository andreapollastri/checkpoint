<?php

namespace Checkpoint\Checks;

use Checkpoint\ScanPaths;
use Symfony\Component\Finder\Finder;

class SsrfCheck extends AbstractCheck
{
    private const USER_INPUT_SOURCES = 'request|_GET|_POST|_REQUEST|input';

    public function __construct(private readonly string $basePath) {}

    public function name(): string
    {
        return 'SSRF Risks';
    }

    public function run(): CheckResult
    {
        $finder = ScanPaths::configure(new Finder(), ScanPaths::WITH_TESTS);
        $finder->files()
            ->in($this->basePath)
            ->name('*.php');

        $findings = [];
        $userInput = self::USER_INPUT_SOURCES;

        foreach ($finder as $file) {
            $lines = explode("\n", $file->getContents());
            $relative = ltrim(str_replace($this->basePath, '', $file->getRealPath()), '/');

            foreach ($lines as $i => $line) {
                // Laravel HTTP client: Http::get($request->...), Http::post(..., ...)
                if (preg_match('/\bHttp::(?:get|post|put|patch|delete|head|send)\s*\(\s*\$(?:'.$userInput.')\b/', $line)) {
                    $findings[] = "{$relative}:".($i + 1).' — Http:: called with user-controlled URL: '.mb_strimwidth(trim($line), 0, 120, '…');
                    continue;
                }

                // Guzzle: $client->request('GET', $request->...) or ->get($request->...)
                if (preg_match('/->(?:request|get|post|put|patch|delete|head|send)\s*\(\s*(?:["\'][A-Z]+["\']\s*,\s*)?\$(?:'.$userInput.')\b/', $line)) {
                    if (preg_match('/Guzzle|GuzzleHttp|HttpClient|Client/', $line) || str_contains($file->getContents(), 'GuzzleHttp')) {
                        $findings[] = "{$relative}:".($i + 1).' — HTTP client called with user-controlled URL: '.mb_strimwidth(trim($line), 0, 120, '…');
                        continue;
                    }
                }

                // file_get_contents / fopen / get_headers with user input directly
                if (preg_match('/\b(?:file_get_contents|fopen|get_headers|readfile)\s*\(\s*\$(?:'.$userInput.')\b/', $line)) {
                    $findings[] = "{$relative}:".($i + 1).' — '.$this->extractFunctionName($line).' with user-controlled URL: '.mb_strimwidth(trim($line), 0, 120, '…');
                    continue;
                }

                // curl_setopt(..., CURLOPT_URL, $request->...)
                if (preg_match('/curl_setopt\s*\([^,]+,\s*CURLOPT_URL\s*,\s*\$(?:'.$userInput.')\b/', $line)) {
                    $findings[] = "{$relative}:".($i + 1).' — curl_setopt(CURLOPT_URL) with user-controlled URL: '.mb_strimwidth(trim($line), 0, 120, '…');
                    continue;
                }
            }
        }

        if (empty($findings)) {
            return CheckResult::pass('No obvious SSRF risks detected.');
        }

        return CheckResult::fail(count($findings).' potential SSRF risk(s) found.', $findings);
    }

    private function extractFunctionName(string $line): string
    {
        if (preg_match('/\b(file_get_contents|fopen|get_headers|readfile)\s*\(/', $line, $m)) {
            return $m[1].'()';
        }

        return 'HTTP call';
    }
}
