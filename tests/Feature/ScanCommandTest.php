<?php

namespace Checkpoint\Tests\Feature;

use Checkpoint\Tests\TestCase;
use Illuminate\Support\Facades\Artisan;

class ScanCommandTest extends TestCase
{
    /**
     * Point the application base path at a controlled workspace so the scan is
     * deterministic. Testbench rebuilds the app per test, so this never leaks.
     */
    private function bootWorkspace(): string
    {
        $workspace = $this->makeWorkspace();

        // A complete .gitignore keeps the GitIgnore check from FAILing, so the
        // only failure in these tests is the one we deliberately introduce.
        $this->writeFile($workspace, '.gitignore', implode("\n", [
            '.env', '*.key', '*.pem', 'storage/logs', '.env.backup', '.env.production',
        ])."\n");

        $this->app->setBasePath($workspace);

        return $workspace;
    }

    public function test_command_fails_when_a_hardcoded_secret_is_present(): void
    {
        $workspace = $this->bootWorkspace();
        $this->writeFile(
            $workspace,
            'app/Services/PaymentService.php',
            "<?php\nreturn ['api_key' => 'sk_live_abcdefghijABCDEFGHIJ1234'];\n",
        );

        $exitCode = Artisan::call('checkpoint:scan');
        $output = Artisan::output();

        $this->assertSame(1, $exitCode);
        $this->assertStringContainsString('Hardcoded Secrets', $output);
        $this->assertStringContainsString('Scan result: FAIL', $output);
    }

    public function test_skip_option_removes_a_check_from_the_run(): void
    {
        $workspace = $this->bootWorkspace();
        $this->writeFile(
            $workspace,
            'app/Services/PaymentService.php',
            "<?php\nreturn ['api_key' => 'sk_live_abcdefghijABCDEFGHIJ1234'];\n",
        );

        $exitCode = Artisan::call('checkpoint:scan', ['--skip' => 'Hardcoded Secrets']);
        $output = Artisan::output();

        $this->assertSame(0, $exitCode);
        $this->assertStringNotContainsString('Hardcoded Secrets', $output);
    }

    public function test_only_option_restricts_output_to_a_single_check(): void
    {
        $this->bootWorkspace();

        Artisan::call('checkpoint:scan', ['--only' => 'Environment Configuration']);
        $output = Artisan::output();

        $this->assertStringContainsString('Environment Configuration', $output);
        $this->assertStringNotContainsString('SQL Injection Risks', $output);
    }

    public function test_json_output_is_valid_and_structured(): void
    {
        $workspace = $this->bootWorkspace();
        $this->writeFile(
            $workspace,
            'app/Services/PaymentService.php',
            "<?php\nreturn ['api_key' => 'sk_live_abcdefghijABCDEFGHIJ1234'];\n",
        );

        $exitCode = Artisan::call('checkpoint:scan', ['--json' => true]);
        $payload = json_decode(Artisan::output(), true);

        $this->assertSame(1, $exitCode);
        $this->assertIsArray($payload);

        $secrets = collect($payload)->firstWhere('check', 'Hardcoded Secrets');
        $this->assertNotNull($secrets);
        $this->assertSame('fail', $secrets['status']);
        $this->assertArrayHasKey('hashes', $secrets);
        $this->assertNotEmpty($secrets['hashes']);
    }

    public function test_suppressed_findings_are_filtered_out(): void
    {
        $workspace = $this->bootWorkspace();
        $this->writeFile(
            $workspace,
            'app/Services/PaymentService.php',
            "<?php\nreturn ['api_key' => 'sk_live_abcdefghijABCDEFGHIJ1234'];\n",
        );

        Artisan::call('checkpoint:scan', ['--json' => true]);
        $payload = json_decode(Artisan::output(), true);
        $hash = collect($payload)->firstWhere('check', 'Hardcoded Secrets')['hashes'][0];

        config()->set('checkpoint.suppressed', [$hash]);

        $exitCode = Artisan::call('checkpoint:scan', ['--json' => true]);
        $payload = json_decode(Artisan::output(), true);
        $secrets = collect($payload)->firstWhere('check', 'Hardcoded Secrets');

        $this->assertSame('pass', $secrets['status']);
        $this->assertStringContainsString('suppressed', $secrets['message']);
        $this->assertSame(0, $exitCode);
    }
}
