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

            $relative = self::relativePath($this->basePath, (string) $file->getRealPath());

            // Models that define neither $fillable nor $guarded are NOT flagged:
            // Eloquent defaults to $guarded = ['*'], so every attribute is
            // protected until the developer explicitly opts out.

            // $guarded = [] disables ALL protection; in an abstract base model
            // the empty array is inherited by every child model.
            if (preg_match('/\$guarded\s*=\s*\[\s*\]/', $content)) {
                $findings[] = preg_match('/\babstract\s+class\b/', $content)
                    ? "{$relative}: \$guarded = [] in abstract model — every attribute of its child models is mass-assignable."
                    : "{$relative}: \$guarded = [] — every attribute is mass-assignable.";
                continue;
            }

            // Model::unguard() disables protection globally
            if (preg_match('/Model::unguard\(\)/', $content)) {
                $findings[] = "{$relative}: Model::unguard() detected — mass assignment protection disabled globally.";
                continue;
            }
        }

        if (empty($findings)) {
            return CheckResult::pass('No mass assignment issues detected.');
        }

        return CheckResult::warn(count($findings).' potential mass assignment issue(s).', $findings);
    }
}
