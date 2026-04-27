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

        // Global CSRF: Laravel 5–10 use VerifyCsrfToken in the HTTP kernel; 11+ often use only
        // bootstrap/app.php, where the framework's PreventRequestForgery is on the default web
        // stack (class name in vendor, not necessarily referenced in app code). Treat either
        // class name in app code as present, and bootstrap-only apps as OK unless web(remove:)
        // clearly strips CSRF middleware.
        $kernelPath = $this->basePath.'/app/Http/Kernel.php';
        $bootstrapPath = $this->basePath.'/bootstrap/app.php';

        $middlewareSourceExists = file_exists($kernelPath) || file_exists($bootstrapPath);
        $kernelHasCsrf = false;
        $bootstrapContent = file_exists($bootstrapPath) ? (string) file_get_contents($bootstrapPath) : '';

        if (file_exists($kernelPath)) {
            $kernelContent = (string) file_get_contents($kernelPath);
            $kernelHasCsrf = $this->appSourceReferencesGlobalCsrf($kernelContent);
        }

        $bootstrapHasCsrf = $bootstrapContent !== '' && $this->appSourceReferencesGlobalCsrf($bootstrapContent);

        $onlyBootstrap = ! file_exists($kernelPath) && file_exists($bootstrapPath);
        $csrfPresent = $kernelHasCsrf
            || $bootstrapHasCsrf
            || ($onlyBootstrap && ! $this->csrfMiddlewareRemovedFromWebInBootstrap($bootstrapContent));

        if ($middlewareSourceExists && ! $csrfPresent) {
            $findings[] = 'CSRF middleware (VerifyCsrfToken / PreventRequestForgery) not found in Kernel/bootstrap, or web group appears to remove it — check that CSRF is not disabled globally.';
        }

        if (empty($findings)) {
            return CheckResult::pass('CSRF protection appears to be in place.');
        }

        return CheckResult::fail(count($findings).' CSRF issue(s) found.', $findings);
    }

    /**
     * True when the app’s own code references the framework CSRF guard (legacy or current name).
     */
    private function appSourceReferencesGlobalCsrf(string $content): bool
    {
        return str_contains($content, 'VerifyCsrfToken')
            || str_contains($content, 'PreventRequestForgery');
    }

    /**
     * Detects $middleware->web(remove: [ …PreventRequestForgery / VerifyCsrf… ]) in bootstrap/app.php.
     */
    private function csrfMiddlewareRemovedFromWebInBootstrap(string $bootstrap): bool
    {
        if (! preg_match('/->web\s*\(\s*remove:\s*\[/s', $bootstrap, $m, PREG_OFFSET_CAPTURE)) {
            return false;
        }

        $from = (int) $m[0][1];
        $chunk = substr($bootstrap, $from, 3000);

        return (bool) preg_match(
            '/PreventRequestForgery|VerifyCsrfToken|ValidateCsrfToken/i',
            $chunk
        );
    }
}
