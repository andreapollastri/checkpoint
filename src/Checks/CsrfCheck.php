<?php

namespace Checkpoint\Checks;

use Symfony\Component\Finder\Finder;

class CsrfCheck extends AbstractCheck
{
    public function __construct(private readonly string $basePath) {}

    public function name(): string
    {
        return 'CSRF Protection';
    }

    public function run(): CheckResult
    {
        $viewsPath = $this->basePath.'/resources/views';

        if (! is_dir($viewsPath)) {
            return CheckResult::warn('resources/views/ not found — skipping CSRF check.');
        }

        $finder = new Finder();
        $finder->files()->in($viewsPath)->name('*.blade.php');

        $findings = [];

        foreach ($finder as $file) {
            $content = $file->getContents();
            $relative = ltrim(str_replace($this->basePath, '', $file->getRealPath()), '/');

            // Find forms with a mutable HTTP method that lack a CSRF token
            if (preg_match_all('/<form\b[^>]*method=["\'](?:POST|PUT|PATCH|DELETE)["\'][^>]*>/i', $content, $matches)) {
                $hasCsrf = str_contains($content, '@csrf')
                    || str_contains($content, 'csrf_field()')
                    || str_contains($content, 'csrf_token()');

                if (! $hasCsrf) {
                    $findings[] = "{$relative}: ".count($matches[0])." form(s) with POST/PUT/PATCH/DELETE but no @csrf directive.";
                }
            }
        }

        // Check that VerifyCsrfToken middleware is not accidentally removed
        $kernelPath = $this->basePath.'/app/Http/Kernel.php';
        $bootstrapPath = $this->basePath.'/bootstrap/app.php';

        $middlewareSourceExists = file_exists($kernelPath) || file_exists($bootstrapPath);
        $csrfPresent = false;

        if (file_exists($kernelPath)) {
            $csrfPresent = str_contains(file_get_contents($kernelPath), 'VerifyCsrfToken');
        }

        if (file_exists($bootstrapPath) && ! $csrfPresent) {
            $bootstrapContent = file_get_contents($bootstrapPath);
            $csrfPresent = str_contains($bootstrapContent, 'VerifyCsrfToken')
                || str_contains($bootstrapContent, 'csrf');
        }

        if ($middlewareSourceExists && ! $csrfPresent) {
            $findings[] = 'VerifyCsrfToken middleware not found in Kernel/bootstrap — CSRF protection may be disabled globally.';
        }

        if (empty($findings)) {
            return CheckResult::pass('CSRF protection appears to be in place.');
        }

        return CheckResult::fail(count($findings).' CSRF issue(s) found.', $findings);
    }
}
