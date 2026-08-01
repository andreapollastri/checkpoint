<?php

namespace Checkpoint\Tests\Unit\Checks;

use Checkpoint\Checks\AbstractCheck;
use Checkpoint\Checks\CheckResult;
use Checkpoint\Tests\TestCase;

class AbstractCheckTest extends TestCase
{
    public function test_relative_path_strips_only_the_leading_base_path(): void
    {
        $this->assertSame(
            'app/Http/Controllers/Foo.php',
            AbstractCheck::relativePath('/app', '/app/app/Http/Controllers/Foo.php'),
        );
    }

    public function test_relative_path_does_not_collapse_repeated_path_segments(): void
    {
        // str_replace($basePath, '', ...) would incorrectly yield Http/Controllers/Foo.php
        $this->assertNotSame(
            'Http/Controllers/Foo.php',
            AbstractCheck::relativePath('/app', '/app/app/Http/Controllers/Foo.php'),
        );
    }

    public function test_relative_path_works_for_unique_project_roots(): void
    {
        $this->assertSame(
            'app/Models/User.php',
            AbstractCheck::relativePath(
                '/Users/dev/projects/myapp',
                '/Users/dev/projects/myapp/app/Models/User.php',
            ),
        );
    }

    public function test_relative_path_is_used_by_checks_for_finding_details(): void
    {
        $workspace = $this->makeWorkspace();
        $this->writeFile(
            $workspace,
            'app/Http/Controllers/UserController.php',
            "<?php\nclass UserController {\n    public function show(\$user) { dd(\$user); }\n}\n",
        );

        $check = new class($workspace) extends AbstractCheck
        {
            public function __construct(private readonly string $basePath) {}

            public function name(): string
            {
                return 'Relative Path Probe';
            }

            public function run(): CheckResult
            {
                $absolute = $this->basePath.'/app/Http/Controllers/UserController.php';

                return CheckResult::fail('probe', [
                    self::relativePath($this->basePath, $absolute),
                ]);
            }
        };

        $result = $check->run();

        $this->assertSame('app/Http/Controllers/UserController.php', $result->details[0]);
    }
}
