<?php

namespace Checkpoint\Tests\Unit\Checks;

use Checkpoint\Checks\CheckResult;
use Checkpoint\Checks\EnvironmentCheck;
use Checkpoint\Tests\TestCase;

class EnvironmentCheckTest extends TestCase
{
    public function test_passes_with_production_safe_configuration(): void
    {
        config()->set('app.debug', false);
        config()->set('app.env', 'production');
        config()->set('app.key', 'base64:'.base64_encode(random_bytes(32)));
        config()->set('app.url', 'https://example.com');
        config()->set('session.secure', true);
        config()->set('session.driver', 'file');

        $workspace = $this->makeWorkspace();
        $this->writeFile($workspace, '.env', "APP_ENV=production\n");

        $result = (new EnvironmentCheck($workspace))->run();

        $this->assertSame(CheckResult::PASS, $result->status);
    }

    public function test_warns_when_app_debug_is_enabled(): void
    {
        config()->set('app.debug', true);
        config()->set('app.env', 'production');
        config()->set('app.key', 'base64:'.base64_encode(random_bytes(32)));
        config()->set('app.url', 'https://example.com');
        config()->set('session.secure', true);

        $workspace = $this->makeWorkspace();
        $this->writeFile($workspace, '.env', "\n");

        $result = (new EnvironmentCheck($workspace))->run();

        $this->assertSame(CheckResult::WARN, $result->status);
        $this->assertStringContainsString('APP_DEBUG', implode("\n", $result->details));
    }

    public function test_warns_when_app_key_is_missing(): void
    {
        config()->set('app.debug', false);
        config()->set('app.env', 'production');
        config()->set('app.key', null);
        config()->set('app.url', 'https://example.com');
        config()->set('session.secure', true);

        $workspace = $this->makeWorkspace();
        $this->writeFile($workspace, '.env', "\n");

        $result = (new EnvironmentCheck($workspace))->run();

        $this->assertSame(CheckResult::WARN, $result->status);
        $this->assertStringContainsString('APP_KEY', implode("\n", $result->details));
    }

    public function test_warns_when_env_file_is_missing(): void
    {
        config()->set('app.debug', false);
        config()->set('app.env', 'production');
        config()->set('app.key', 'base64:'.base64_encode(random_bytes(32)));
        config()->set('app.url', 'https://example.com');
        config()->set('session.secure', true);

        $workspace = $this->makeWorkspace();

        $result = (new EnvironmentCheck($workspace))->run();

        $this->assertSame(CheckResult::WARN, $result->status);
        $this->assertStringContainsString('.env file not found', implode("\n", $result->details));
    }

    public function test_flags_localhost_app_url(): void
    {
        config()->set('app.debug', false);
        config()->set('app.env', 'production');
        config()->set('app.key', 'base64:'.base64_encode(random_bytes(32)));
        config()->set('app.url', 'http://localhost');
        config()->set('session.secure', true);

        $workspace = $this->makeWorkspace();
        $this->writeFile($workspace, '.env', "\n");

        $result = (new EnvironmentCheck($workspace))->run();

        $this->assertSame(CheckResult::WARN, $result->status);
        $this->assertStringContainsString('APP_URL', implode("\n", $result->details));
    }
}
