<?php

namespace Checkpoint\Commands;

use Illuminate\Console\Command;

class InstallHooksCommand extends Command
{
    protected $signature = 'checkpoint:install-hooks
                            {--force : Replace any existing Checkpoint entry instead of leaving it untouched}
                            {--remove : Remove Checkpoint entries from composer.json}';

    protected $description = 'Wire `php artisan checkpoint:scan` into composer.json as a post-update / post-install hook';

    private const HOOK_COMMAND = '@php artisan checkpoint:scan';
    private const HOOK_EVENTS = ['post-update-cmd', 'post-install-cmd'];
    private const MARKER = 'checkpoint:scan';

    public function handle(): int
    {
        $composerPath = base_path('composer.json');

        if (! file_exists($composerPath)) {
            $this->error('  composer.json not found in the project root.');

            return Command::FAILURE;
        }

        $raw = file_get_contents($composerPath);
        $manifest = json_decode($raw, true);

        if (! is_array($manifest)) {
            $this->error('  composer.json is not valid JSON.');

            return Command::FAILURE;
        }

        $original = $manifest;

        if ($this->option('remove')) {
            $manifest = $this->removeHooks($manifest);
            $verb = 'remove';
        } else {
            $manifest = $this->addHooks($manifest, (bool) $this->option('force'));
            $verb = 'install';
        }

        if ($manifest === $original) {
            $this->info('  composer.json is already in the desired state — nothing to do.');

            return Command::SUCCESS;
        }

        $this->newLine();
        $this->line("  Checkpoint is about to <options=bold>{$verb}</> the following composer hooks:");
        foreach (self::HOOK_EVENTS as $event) {
            $this->line("    • scripts.{$event} → ".self::HOOK_COMMAND);
        }
        $this->newLine();
        $this->warn('  This will rewrite composer.json (formatting may be normalized).');

        if (! $this->confirm('  Proceed?', true)) {
            $this->line('  <fg=gray>Aborted — composer.json unchanged.</>');

            return Command::SUCCESS;
        }

        $json = json_encode($manifest, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
        if ($json === false) {
            $this->error('  Failed to re-encode composer.json.');

            return Command::FAILURE;
        }

        if (file_put_contents($composerPath, $json."\n") === false) {
            $this->error('  Failed to write composer.json.');

            return Command::FAILURE;
        }

        $this->newLine();
        $this->line("  <fg=green;options=bold>  ✓</>  Checkpoint hooks {$verb}d in composer.json");
        $this->line('  <fg=gray>Run `composer validate` to confirm the file is still valid.</>');
        $this->newLine();

        return Command::SUCCESS;
    }

    /**
     * @param  array<string, mixed>  $manifest
     * @return array<string, mixed>
     */
    private function addHooks(array $manifest, bool $force): array
    {
        $manifest['scripts'] ??= [];

        foreach (self::HOOK_EVENTS as $event) {
            $existing = $manifest['scripts'][$event] ?? null;

            if ($existing === null) {
                $manifest['scripts'][$event] = [self::HOOK_COMMAND];

                continue;
            }

            $entries = is_array($existing) ? $existing : [$existing];

            if ($this->containsCheckpoint($entries) && ! $force) {
                continue;
            }

            if ($force) {
                $entries = $this->stripCheckpoint($entries);
            }

            $entries[] = self::HOOK_COMMAND;
            $manifest['scripts'][$event] = array_values($entries);
        }

        return $manifest;
    }

    /**
     * @param  array<string, mixed>  $manifest
     * @return array<string, mixed>
     */
    private function removeHooks(array $manifest): array
    {
        if (! isset($manifest['scripts']) || ! is_array($manifest['scripts'])) {
            return $manifest;
        }

        foreach (self::HOOK_EVENTS as $event) {
            if (! isset($manifest['scripts'][$event])) {
                continue;
            }

            $existing = $manifest['scripts'][$event];
            $entries = is_array($existing) ? $existing : [$existing];
            $entries = $this->stripCheckpoint($entries);

            if (empty($entries)) {
                unset($manifest['scripts'][$event]);
            } else {
                $manifest['scripts'][$event] = array_values($entries);
            }
        }

        if (empty($manifest['scripts'])) {
            unset($manifest['scripts']);
        }

        return $manifest;
    }

    /**
     * @param  array<int, mixed>  $entries
     */
    private function containsCheckpoint(array $entries): bool
    {
        foreach ($entries as $entry) {
            if (is_string($entry) && str_contains($entry, self::MARKER)) {
                return true;
            }
        }

        return false;
    }

    /**
     * @param  array<int, mixed>  $entries
     * @return array<int, mixed>
     */
    private function stripCheckpoint(array $entries): array
    {
        return array_values(array_filter(
            $entries,
            fn ($entry) => ! is_string($entry) || ! str_contains($entry, self::MARKER),
        ));
    }
}
