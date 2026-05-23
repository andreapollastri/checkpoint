<?php

namespace Checkpoint\Checks;

class CorsConfigCheck extends AbstractCheck
{
    public function __construct(private readonly string $basePath) {}

    public function name(): string
    {
        return 'CORS Configuration';
    }

    public function run(): CheckResult
    {
        $configPath = $this->basePath.'/config/cors.php';

        if (! file_exists($configPath)) {
            return CheckResult::pass('No config/cors.php file found — CORS not configured.');
        }

        $content = file_get_contents($configPath);
        $findings = [];

        $allowsAllOrigins = preg_match("/'allowed_origins'\s*=>\s*\[\s*['\"]\\*['\"]\s*\]/", $content) === 1;
        $allowsAllOriginsPatterns = preg_match("/'allowed_origins_patterns'\s*=>\s*\[\s*['\"]\\.\\*['\"]\s*\]/", $content) === 1;
        $supportsCredentials = preg_match("/'supports_credentials'\s*=>\s*true/", $content) === 1;
        $allowsAllHeaders = preg_match("/'allowed_headers'\s*=>\s*\[\s*['\"]\\*['\"]\s*\]/", $content) === 1;
        $allowsAllMethods = preg_match("/'allowed_methods'\s*=>\s*\[\s*['\"]\\*['\"]\s*\]/", $content) === 1;

        // The combo wildcard origins + credentials is the critical CORS misconfig
        if (($allowsAllOrigins || $allowsAllOriginsPatterns) && $supportsCredentials) {
            $findings[] = "config/cors.php: allowed_origins '*' combined with supports_credentials => true — exposes authenticated endpoints to any origin (CRITICAL).";
        } elseif ($allowsAllOrigins || $allowsAllOriginsPatterns) {
            $findings[] = "config/cors.php: allowed_origins is '*' — restrict to known origins in production.";
        }

        if ($allowsAllHeaders && $supportsCredentials) {
            $findings[] = "config/cors.php: allowed_headers '*' combined with supports_credentials => true — allows arbitrary headers on credentialed requests.";
        }

        // Wildcard methods are not by themselves dangerous but worth a heads-up
        if ($allowsAllMethods) {
            $findings[] = "config/cors.php: allowed_methods is '*' — explicitly list only the methods you intend to expose.";
        }

        // Paths set to '*' or empty array means CORS applies to everything
        if (preg_match("/'paths'\s*=>\s*\[\s*['\"]\\*['\"]\s*\]/", $content)) {
            $findings[] = "config/cors.php: paths is '*' — CORS rules apply to every route, including non-API ones.";
        }

        if (empty($findings)) {
            return CheckResult::pass('CORS configuration looks reasonable.');
        }

        // Critical combo (origins '*' + credentials) is a FAIL, others WARN
        $isCritical = ($allowsAllOrigins || $allowsAllOriginsPatterns) && $supportsCredentials;

        return $isCritical
            ? CheckResult::fail(count($findings).' CORS issue(s) found.', $findings)
            : CheckResult::warn(count($findings).' CORS issue(s) found.', $findings);
    }
}
