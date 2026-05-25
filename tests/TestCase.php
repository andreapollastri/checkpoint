<?php

namespace Checkpoint\Tests;

use Checkpoint\CheckpointServiceProvider;
use Orchestra\Testbench\TestCase as Orchestra;

class TestCase extends Orchestra
{
    protected function getPackageProviders($app)
    {
        return [
            CheckpointServiceProvider::class,
        ];
    }
}
