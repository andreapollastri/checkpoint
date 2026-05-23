<?php

namespace Checkpoint\Checks;

use Symfony\Component\Finder\Finder;

class MassAssignmentCheck extends AbstractCheck
{
    public function __construct(private readonly string $basePath) {}

    public function name(): string
    {
        return 'Mass Assignment Vulnerabilities';
    }

    public function run(): CheckResult
    {
        $modelsPath = $this->basePath.'/app';

        if (! is_dir($modelsPath)) {
            return CheckResult::warn('app/ directory not found — skipping mass assignment check.');
        }

        $finder = new Finder();
        $finder->files()
            ->in($modelsPath)
            ->name('*.php');

        $findings = [];

        foreach ($finder as $file) {
            $content = $file->getContents();

            if (! preg_match('/extends\s+(?:Model|Authenticatable|Pivot)\b/', $content)) {
                continue;
            }

            $relative = ltrim(str_replace($this->basePath, '', $file->getRealPath()), '/');

            // $guarded = [] disables ALL protection
            if (preg_match('/\$guarded\s*=\s*\[\s*\]/', $content)) {
                $findings[] = "{$relative}: \$guarded = [] — every attribute is mass-assignable.";
                continue;
            }

            // Model::unguard() disables protection globally
            if (preg_match('/Model::unguard\(\)/', $content)) {
                $findings[] = "{$relative}: Model::unguard() detected — mass assignment protection disabled globally.";
                continue;
            }

            // Neither $fillable nor $guarded defined
            $hasFillable = (bool) preg_match('/(?:\$fillable\s*=|#\[Fillable\b)/', $content);
            $hasGuarded = (bool) preg_match('/(?:\$guarded\s*=|#\[Guarded\b)/', $content);

            if (! $hasFillable && ! $hasGuarded) {
                $findings[] = "{$relative}: Model has neither \$fillable nor \$guarded — all attributes are unprotected.";
            }
        }

        if (empty($findings)) {
            return CheckResult::pass('No mass assignment issues detected.');
        }

        return CheckResult::warn(count($findings).' potential mass assignment issue(s).', $findings);
    }
}
