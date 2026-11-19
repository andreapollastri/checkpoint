<?php

namespace Checkpoint\Tests;

use Checkpoint\CheckpointServiceProvider;
use Checkpoint\Tests\Concerns\CreatesWorkspace;
use Orchestra\Testbench\TestCase as Orchestra;

abstract class TestCase extends Orchestra
{
    use CreatesWorkspace;

    protected function tearDown(): void
    {
        $this->cleanWorkspaces();

        parent::tearDown();
    }

    /**
     * Keep the suite hermetic: the PHP CVE Audit check must not call php.net.
     *
     * @param  \Illuminate\Foundation\Application  $app
     */
    protected function defineEnvironment($app): void
    {
        $app['config']->set('checkpoint.php_cve.live_lookup', false);
    }

    /**
     * @param  \Illuminate\Foundation\Application  $app
     * @return array<int, class-string>
     */
    protected function getPackageProviders($app): array
    {
        return [
            CheckpointServiceProvider::class,
        ];
    }
}
