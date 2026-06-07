<?php

namespace Checkpoint\Checks;

use Checkpoint\ScanPaths;
use Symfony\Component\Finder\Finder;

class PathTraversalCheck extends AbstractCheck
{
    private const USER_INPUT = 'request|_GET|_POST|_REQUEST|input';

    public function __construct(private readonly string $basePath) {}

    public function name(): string
    {
        return 'Path Traversal Risks';
    }

    public function run(): CheckResult
    {
        $finder = ScanPaths::configure(new Finder(), ScanPaths::WITH_TESTS);
        $finder->files()
            ->in($this->basePath)
            ->name('*.php');

        $findings = [];
        $userInput = self::USER_INPUT;

        foreach ($finder as $file) {
            $lines = explode("\n", $file->getContents());
            $relative = ltrim(str_replace($this->basePath, '', $file->getRealPath()), '/');

            foreach ($lines as $i => $line) {
                // Skip lines that include the standard sanitizers
                if (preg_match('/\b(?:basename|realpath|pathinfo)\s*\(/', $line)) {
                    continue;
                }

                // Storage::get/put/etc. with user input as first argument
                if (preg_match('/Storage::(?:disk\([^)]*\)->)?(?:get|put|putFileAs|move|copy|delete|download|readStream|writeStream)\s*\(\s*\$(?:'.$userInput.')\b/', $line)) {
                    $findings[] = "{$relative}:".($i + 1).' — Storage:: with user-controlled path: '.mb_strimwidth(trim($line), 0, 120, '…');

                    continue;
                }

                // file_get_contents / fopen / readfile / file_put_contents with user input
                if (preg_match('/\b(file_get_contents|fopen|readfile|file_put_contents)\s*\(\s*\$(?:'.$userInput.')\b/', $line, $m)) {
                    $findings[] = "{$relative}:".($i + 1).' — '.$m[1].'() with user-controlled path: '.mb_strimwidth(trim($line), 0, 120, '…');

                    continue;
                }

                // include / require with user input
                if (preg_match('/\b(include|include_once|require|require_once)\s+\$(?:'.$userInput.')\b/', $line, $m)) {
                    $findings[] = "{$relative}:".($i + 1).' — '.$m[1].' with user-controlled path: '.mb_strimwidth(trim($line), 0, 120, '…');

                    continue;
                }

                // String concatenation: 'storage/' . $request->… inside a file/storage call
                if (preg_match('/(?:file_get_contents|fopen|readfile|file_put_contents|Storage::|include|require)\b[^;]*[\'\"]\w+[\'\"]\s*\.\s*\$(?:'.$userInput.')\b/', $line)) {
                    $findings[] = "{$relative}:".($i + 1).' — file operation with concatenated user input: '.mb_strimwidth(trim($line), 0, 120, '…');
                }
            }
        }

        if (empty($findings)) {
            return CheckResult::pass('No obvious path traversal risks detected.');
        }

        return CheckResult::fail(count($findings).' potential path traversal risk(s) found.', $findings);
    }
}
