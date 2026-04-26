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
        return (new static)
            ->add(new Checks\ComposerAuditCheck($basePath))
            ->add(new Checks\NpmAuditCheck($basePath))
            ->add(new Checks\EnvironmentCheck($basePath))
            ->add(new Checks\GitIgnoreCheck($basePath))
            ->add(new Checks\FilePermissionsCheck($basePath))
            ->add(new Checks\HardcodedSecretsCheck($basePath))
            ->add(new Checks\SqlInjectionCheck($basePath))
            ->add(new Checks\MassAssignmentCheck($basePath))
            ->add(new Checks\XssCheck($basePath))
            ->add(new Checks\CsrfCheck($basePath))
            ->add(new Checks\OpenRedirectCheck($basePath))
            ->add(new Checks\CommandInjectionCheck($basePath))
            ->add(new Checks\InsecureDeserializationCheck($basePath))
            ->add(new Checks\DebugFunctionsCheck($basePath))
            ->add(new Checks\SensitiveExposureCheck($basePath));
    }
}
