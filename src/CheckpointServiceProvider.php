<?php

namespace Checkpoint;

use Checkpoint\Commands\ScanCommand;
use Illuminate\Support\ServiceProvider;

class CheckpointServiceProvider extends ServiceProvider
{
    public function boot(): void
    {
        if ($this->app->runningInConsole()) {
            $this->commands([
                ScanCommand::class,
            ]);
        }
    }
}
