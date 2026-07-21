<?php

namespace Checkpoint\Tests\Unit\Checks;

use Checkpoint\Checks\CheckResult;
use Checkpoint\Checks\DebugFunctionsCheck;
use Checkpoint\Tests\TestCase;

class DebugFunctionsCheckTest extends TestCase
{
    public function test_passes_on_a_clean_codebase(): void
    {
        $workspace = $this->makeWorkspace();
        $this->writeFile($workspace, 'app/Services/Clean.php', "<?php\nreturn ['ok' => true];\n");

        $result = (new DebugFunctionsCheck($workspace))->run();

        $this->assertSame(CheckResult::PASS, $result->status);
    }

    public function test_detects_dd_in_application_code(): void
    {
        $workspace = $this->makeWorkspace();
        $this->writeFile(
            $workspace,
            'app/Http/Controllers/UserController.php',
            "<?php\nclass UserController {\n    public function show(\$user) { dd(\$user); }\n}\n",
        );

        $result = (new DebugFunctionsCheck($workspace))->run();

        $this->assertSame(CheckResult::WARN, $result->status);
        $this->assertStringContainsString('UserController.php', $result->details[0]);
    }

    public function test_ignores_debug_calls_in_line_comments(): void
    {
        $workspace = $this->makeWorkspace();
        $this->writeFile(
            $workspace,
            'app/Services/Clean.php',
            "<?php\n// dd(\$debug);\n * dump(\$x);\nreturn true;\n",
        );

        $result = (new DebugFunctionsCheck($workspace))->run();

        $this->assertSame(CheckResult::PASS, $result->status);
    }

    public function test_ignores_debug_calls_under_tests(): void
    {
        $workspace = $this->makeWorkspace();
        $this->writeFile(
            $workspace,
            'tests/Feature/ExampleTest.php',
            "<?php\ndd('only in tests');\n",
        );

        $result = (new DebugFunctionsCheck($workspace))->run();

        $this->assertSame(CheckResult::PASS, $result->status);
    }

    public function test_name_is_stable(): void
    {
        $this->assertSame(
            'Debug Functions in Production Code',
            (new DebugFunctionsCheck($this->makeWorkspace()))->name(),
        );
    }
}
