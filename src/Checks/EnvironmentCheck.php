<?php

namespace Checkpoint\Checks;

class EnvironmentCheck extends AbstractCheck
{
    public function __construct(private readonly string $basePath) {}

    public function name(): string
    {
        return 'Environment Configuration';
    }

    public function run(): CheckResult
    {
        $issues = [];

        if (config('app.debug') === true) {
            $issues[] = 'APP_DEBUG is true — full stack traces will be exposed to end users.';
        }

        if (in_array(config('app.env'), ['local', 'development', 'dev'], true)) {
            $issues[] = 'APP_ENV is "'.config('app.env').'" — set to "production" in production environments.';
        }

        if (empty(config('app.key'))) {
            $issues[] = 'APP_KEY is not set — encryption, sessions and cookies are insecure.';
        }

        if (! file_exists($this->basePath.'/.env')) {
            $issues[] = '.env file not found.';
        }

        // Check that APP_URL is not the default localhost
        $appUrl = config('app.url', '');
        if (str_contains($appUrl, 'localhost') || str_contains($appUrl, '127.0.0.1')) {
            $issues[] = "APP_URL is set to \"{$appUrl}\" — update it for production.";
        }

        // Warn if SESSION_SECURE_COOKIE is not enabled
        if (config('session.secure') !== true) {
            $issues[] = 'SESSION_SECURE_COOKIE is not enabled — session cookies will be sent over plain HTTP.';
        }

        // Warn if session driver is not production-safe
        $sessionDriver = config('session.driver', 'file');
        if ($sessionDriver === 'array') {
            $issues[] = 'Session driver is "array" — sessions will not persist between requests.';
        }

        if (empty($issues)) {
            return CheckResult::pass('Environment configuration looks good.');
        }

        return CheckResult::warn(count($issues).' environment issue(s) found.', $issues);
    }
}
