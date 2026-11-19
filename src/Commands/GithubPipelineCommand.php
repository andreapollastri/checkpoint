<?php

namespace Checkpoint\Commands;

use Illuminate\Console\Command;

class GithubPipelineCommand extends Command
{
    protected $signature = 'checkpoint:github
                            {--force : Overwrite the workflow file if it already exists}
                            {--php= : PHP version for the workflow, e.g. 8.6 (defaults to the PHP running this command)}';

    protected $description = 'Scaffold a GitHub Actions workflow that runs checkpoint:scan on push and pull requests';

    public function handle(): int
    {
        $stubPath = __DIR__.'/../../stubs/github-workflow.yml';
        $targetPath = base_path('.github/workflows/checkpoint.yml');

        $phpVersion = (string) ($this->option('php') ?: PHP_MAJOR_VERSION.'.'.PHP_MINOR_VERSION);

        if (! preg_match('/^\d+\.\d+$/', $phpVersion)) {
            $this->error("  Invalid --php value \"{$phpVersion}\". Use a major.minor version such as 8.6.");

            return Command::FAILURE;
        }

        if (file_exists($targetPath) && ! $this->option('force')) {
            $this->error('  .github/workflows/checkpoint.yml already exists. Pass --force to overwrite.');

            return Command::FAILURE;
        }

        $targetDir = dirname($targetPath);
        if (! is_dir($targetDir) && ! mkdir($targetDir, 0755, true) && ! is_dir($targetDir)) {
            $this->error("  Could not create directory: {$targetDir}");

            return Command::FAILURE;
        }

        $workflow = str_replace('{{ php_version }}', $phpVersion, (string) file_get_contents($stubPath));

        if (file_put_contents($targetPath, $workflow) === false) {
            $this->error('  Failed to write the workflow file.');

            return Command::FAILURE;
        }

        $this->newLine();
        $this->line('  <fg=green;options=bold>  ✓</>  GitHub Actions workflow created at <options=bold>.github/workflows/checkpoint.yml</>');
        $this->line("  <fg=gray>Commit the file and push — Checkpoint will run on PHP {$phpVersion} on every push to main/master and on every pull request.</>");
        $this->newLine();

        return Command::SUCCESS;
    }
}
