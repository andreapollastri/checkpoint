<?php

namespace Checkpoint;

use Checkpoint\Checks\AbstractCheck;
use Checkpoint\Checks\CheckResult;

class Scanner
{
    /** @var AbstractCheck[] */
    private array $checks = [];

    public function add(AbstractCheck $check): static
    {
        $this->checks[] = $check;

        return $this;
    }

    /**
     * @return array<string, CheckResult>
     */
    public function run(): array
    {
        $results = [];

        foreach ($this->checks as $check) {
            $results[$check->name()] = $check->run();
        }

        return $results;
    }

    public static function withDefaultChecks(string $basePath): static
    {
        $factories = [
            Checks\ComposerAuditCheck::class => fn () => new Checks\ComposerAuditCheck($basePath),
            Checks\NpmAuditCheck::class => fn () => new Checks\NpmAuditCheck($basePath),
            Checks\EnvironmentCheck::class => fn () => new Checks\EnvironmentCheck($basePath),
            Checks\GitIgnoreCheck::class => fn () => new Checks\GitIgnoreCheck($basePath),
            Checks\FilePermissionsCheck::class => fn () => new Checks\FilePermissionsCheck($basePath),
            Checks\HardcodedSecretsCheck::class => fn () => new Checks\HardcodedSecretsCheck($basePath),
            Checks\SqlInjectionCheck::class => fn () => new Checks\SqlInjectionCheck($basePath),
            Checks\MassAssignmentCheck::class => fn () => new Checks\MassAssignmentCheck($basePath),
            Checks\XssCheck::class => fn () => new Checks\XssCheck($basePath),
            Checks\CsrfCheck::class => fn () => new Checks\CsrfCheck($basePath),
            Checks\OpenRedirectCheck::class => fn () => new Checks\OpenRedirectCheck($basePath),
            Checks\CommandInjectionCheck::class => fn () => new Checks\CommandInjectionCheck($basePath),
            Checks\InsecureDeserializationCheck::class => fn () => new Checks\InsecureDeserializationCheck($basePath),
            Checks\DebugFunctionsCheck::class => fn () => new Checks\DebugFunctionsCheck($basePath),
            Checks\SensitiveExposureCheck::class => fn () => new Checks\SensitiveExposureCheck($basePath),
            Checks\SsrfCheck::class => fn () => new Checks\SsrfCheck($basePath),
            Checks\TlsVerificationCheck::class => fn () => new Checks\TlsVerificationCheck($basePath),
            Checks\CorsConfigCheck::class => fn () => new Checks\CorsConfigCheck($basePath),
            Checks\PackageFreshnessCheck::class => fn () => new Checks\PackageFreshnessCheck(
                $basePath,
                (int) \config('checkpoint.package_freshness.minimum_age_days', 3),
                (array) \config('checkpoint.package_freshness.whitelist', []),
            ),
            Checks\SuspiciousVendorAutoloadCheck::class => fn () => new Checks\SuspiciousVendorAutoloadCheck(
                $basePath,
                (array) \config('checkpoint.suspicious_autoload.whitelist', []),
            ),
            Checks\SupplyChainToolingCheck::class => fn () => new Checks\SupplyChainToolingCheck($basePath),
            Checks\PathTraversalCheck::class => fn () => new Checks\PathTraversalCheck($basePath),
            Checks\WeakCryptographyCheck::class => fn () => new Checks\WeakCryptographyCheck($basePath),
            Checks\InsecureRngCheck::class => fn () => new Checks\InsecureRngCheck($basePath),
            Checks\SessionSecurityCheck::class => fn () => new Checks\SessionSecurityCheck($basePath),
            Checks\EolVersionCheck::class => fn () => new Checks\EolVersionCheck($basePath),
        ];

        $enabled = (array) \config('checkpoint.checks', []);
        $scanner = new static;

        foreach ($factories as $class => $factory) {
            if (($enabled[$class] ?? true) === false) {
                continue;
            }

            $scanner->add($factory());
        }

        return $scanner;
    }
}
