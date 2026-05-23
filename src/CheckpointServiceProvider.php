<?php

namespace Checkpoint;

use Checkpoint\Commands\GithubPipelineCommand;
use Checkpoint\Commands\GitlabPipelineCommand;
use Checkpoint\Commands\ScanCommand;
use Illuminate\Support\ServiceProvider;

class CheckpointServiceProvider extends ServiceProvider
{
    public function register(): void
    {
        $this->mergeConfigFrom(__DIR__.'/../config/checkpoint.php', 'checkpoint');
    }

    public function boot(): void
    {
        if ($this->app->runningInConsole()) {
            $this->commands([
                ScanCommand::class,
                GithubPipelineCommand::class,
                GitlabPipelineCommand::class,
            ]);

            $this->publishes([
                __DIR__.'/../config/checkpoint.php' => config_path('checkpoint.php'),
            ], 'checkpoint-config');
        }
    }
}
