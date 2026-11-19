<?php

namespace Checkpoint\Tests\Feature;

use Checkpoint\Tests\TestCase;
use Illuminate\Support\Facades\Artisan;

class GithubPipelineCommandTest extends TestCase
{
    public function test_workflow_targets_the_php_version_running_the_command(): void
    {
        $workspace = $this->bootWorkspace();

        $exitCode = Artisan::call('checkpoint:github');
        $workflow = (string) file_get_contents($workspace.'/.github/workflows/checkpoint.yml');

        $this->assertSame(0, $exitCode);
        $this->assertStringContainsString("php-version: '".PHP_MAJOR_VERSION.'.'.PHP_MINOR_VERSION."'", $workflow);
        $this->assertStringNotContainsString('php_version', $workflow);
    }

    public function test_php_option_overrides_the_workflow_version(): void
    {
        $workspace = $this->bootWorkspace();

        $exitCode = Artisan::call('checkpoint:github', ['--php' => '8.6']);

        $this->assertSame(0, $exitCode);
        $this->assertStringContainsString(
            "php-version: '8.6'",
            (string) file_get_contents($workspace.'/.github/workflows/checkpoint.yml'),
        );
    }

    public function test_invalid_php_option_is_rejected(): void
    {
        $workspace = $this->bootWorkspace();

        $exitCode = Artisan::call('checkpoint:github', ['--php' => 'latest']);

        $this->assertSame(1, $exitCode);
        $this->assertFileDoesNotExist($workspace.'/.github/workflows/checkpoint.yml');
    }

    public function test_existing_workflow_is_kept_without_force(): void
    {
        $workspace = $this->bootWorkspace();
        $this->writeFile($workspace, '.github/workflows/checkpoint.yml', "name: mine\n");

        $this->assertSame(1, Artisan::call('checkpoint:github'));
        $this->assertSame("name: mine\n", file_get_contents($workspace.'/.github/workflows/checkpoint.yml'));

        $this->assertSame(0, Artisan::call('checkpoint:github', ['--force' => true]));
        $this->assertStringContainsString('Checkpoint Security Scan', (string) file_get_contents($workspace.'/.github/workflows/checkpoint.yml'));
    }

    private function bootWorkspace(): string
    {
        $workspace = $this->makeWorkspace();
        $this->app->setBasePath($workspace);

        return $workspace;
    }
}
