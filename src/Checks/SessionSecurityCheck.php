<?php

namespace Checkpoint\Checks;

class SessionSecurityCheck extends AbstractCheck
{
    public function __construct(private readonly string $basePath) {}

    public function name(): string
    {
        return 'Session & Cookie Security';
    }

    public function run(): CheckResult
    {
        $configPath = $this->basePath.'/config/session.php';

        if (! file_exists($configPath)) {
            return CheckResult::pass('No config/session.php found — skipping session/cookie check.');
        }

        $content = file_get_contents($configPath);
        $findings = [];

        // http_only explicitly disabled — cookies become readable from JavaScript
        if (preg_match("/'http_only'\s*=>\s*false\b/", $content)) {
            $findings[] = "config/session.php: 'http_only' => false — session cookies will be accessible via JavaScript (XSS amplifier).";
        }

        // same_site explicitly null — no protection against cross-origin CSRF
        if (preg_match("/'same_site'\s*=>\s*null\b/", $content)) {
            $findings[] = "config/session.php: 'same_site' => null — set to 'lax' or 'strict' to harden against CSRF.";
        }

        // same_site = 'none' — exposes cookies to cross-site requests
        if (preg_match("/'same_site'\s*=>\s*['\"]none['\"]/i", $content)) {
            $findings[] = "config/session.php: 'same_site' => 'none' — session cookies sent on cross-site requests. Only acceptable for federated auth, and requires 'secure' => true.";
        }

        // secure hardcoded to false (different from env-driven default)
        if (preg_match("/'secure'\s*=>\s*false\b/", $content)) {
            $findings[] = "config/session.php: 'secure' => false (hardcoded) — session cookies will be sent over plain HTTP.";
        }

        // encrypt = false (session payload stored in cleartext)
        if (preg_match("/'encrypt'\s*=>\s*false\b/", $content)) {
            $findings[] = "config/session.php: 'encrypt' => false — session payload is stored in cleartext on the session driver.";
        }

        if (empty($findings)) {
            return CheckResult::pass('Session/cookie configuration looks reasonable.');
        }

        return CheckResult::warn(count($findings).' session/cookie security issue(s) found.', $findings);
    }
}
