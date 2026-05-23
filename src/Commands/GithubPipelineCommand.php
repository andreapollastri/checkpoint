<?php

namespace Checkpoint\Commands;

use Illuminate\Console\Command;

class GithubPipelineCommand extends Command
{
    protected $signature = 'checkpoint:github
                            {--force : Overwrite the workflow file if it already exists}';

    protected $description = 'Scaffold a GitHub Actions workflow that runs checkpoint:scan on push and pull requests';

    public function handle(): int
    {
        $stubPath = __DIR__.'/../../stubs/github-workflow.yml';
        $targetPath = base_path('.github/workflows/checkpoint.yml');

        if (file_exists($targetPath) && ! $this->option('force')) {
            $this->error('  .github/workflows/checkpoint.yml already exists. Pass --force to overwrite.');

            return Command::FAILURE;
        }

        $targetDir = dirname($targetPath);
        if (! is_dir($targetDir) && ! mkdir($targetDir, 0755, true) && ! is_dir($targetDir)) {
            $this->error("  Could not create directory: {$targetDir}");

            return Command::FAILURE;
        }

        if (copy($stubPath, $targetPath) === false) {
            $this->error('  Failed to write the workflow file.');

            return Command::FAILURE;
        }

        $this->newLine();
        $this->line('  <fg=green;options=bold>  ✓</>  GitHub Actions workflow created at <options=bold>.github/workflows/checkpoint.yml</>');
        $this->line('  <fg=gray>Commit the file and push — Checkpoint will run on every push to main/master and on every pull request.</>');
        $this->newLine();

        return Command::SUCCESS;
    }
}
