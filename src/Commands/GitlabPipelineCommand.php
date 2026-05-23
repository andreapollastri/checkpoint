<?php

namespace Checkpoint\Commands;

use Illuminate\Console\Command;

class GitlabPipelineCommand extends Command
{
    protected $signature = 'checkpoint:gitlab
                            {--force : Overwrite .gitlab-ci.yml if it already exists}';

    protected $description = 'Scaffold a .gitlab-ci.yml pipeline that runs checkpoint:scan on merge requests and default branch pushes';

    public function handle(): int
    {
        $stubPath = __DIR__.'/../../stubs/gitlab-ci.yml';
        $targetPath = base_path('.gitlab-ci.yml');

        if (file_exists($targetPath) && ! $this->option('force')) {
            $this->error('  .gitlab-ci.yml already exists. Pass --force to overwrite, or copy the snippet below into your existing pipeline:');
            $this->newLine();
            $this->line(file_get_contents($stubPath));

            return Command::FAILURE;
        }

        if (copy($stubPath, $targetPath) === false) {
            $this->error('  Failed to write .gitlab-ci.yml.');

            return Command::FAILURE;
        }

        $this->newLine();
        $this->line('  <fg=green;options=bold>  ✓</>  GitLab CI pipeline created at <options=bold>.gitlab-ci.yml</>');
        $this->line('  <fg=gray>Commit the file and push — Checkpoint will run on every merge request and on default-branch pushes.</>');
        $this->newLine();

        return Command::SUCCESS;
    }
}
