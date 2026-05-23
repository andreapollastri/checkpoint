<?php

namespace Checkpoint\Commands;

use Checkpoint\Checks\CheckResult;
use Checkpoint\Scanner;
use Illuminate\Console\Command;

class ScanCommand extends Command
{
    protected $signature = 'checkpoint:scan
                            {--only= : Comma-separated list of check names to run}
                            {--skip= : Comma-separated list of check names to skip}
                            {--json  : Output results as JSON}';

    protected $description = 'Run a full security audit of this Laravel application';

    public function handle(): int
    {
        $basePath = base_path();

        if (! $this->option('json')) {
            $this->newLine();
            $this->line('  <fg=cyan;options=bold>  ██████╗██╗  ██╗███████╗ ██████╗██╗  ██╗██████╗  ██████╗ ██╗███╗  ██╗████████╗</>');
            $this->line('  <fg=cyan;options=bold> ██╔════╝██║  ██║██╔════╝██╔════╝██║ ██╔╝██╔══██╗██╔═══██╗██║████╗ ██║╚══██╔══╝</>');
            $this->line('  <fg=cyan;options=bold> ██║     ███████║█████╗  ██║     █████╔╝ ██████╔╝██║   ██║██║██╔██╗██║   ██║   </>');
            $this->line('  <fg=cyan;options=bold> ██║     ██╔══██║██╔══╝  ██║     ██╔═██╗ ██╔═══╝ ██║   ██║██║██║╚████║   ██║   </>');
            $this->line('  <fg=cyan;options=bold>  ╚█████╗██║  ██║███████╗ ╚█████╗██║  ██╗██║      ╚█████╔╝██║██║ ╚███║   ██║   </>');
            $this->line('  <fg=cyan;options=bold>   ╚════╝╚═╝  ╚═╝╚══════╝  ╚════╝╚═╝  ╚═╝╚═╝       ╚════╝ ╚═╝╚═╝  ╚══╝   ╚═╝   </>');
            $this->newLine();
            $this->line('  <fg=gray>Laravel Security Scanner — andreapollastri/checkpoint</>');
            $this->line('  <fg=gray>Scanning: '.$basePath.'</>');
            $this->newLine();
        }

        $scanner = Scanner::withDefaultChecks($basePath);

        $results = $scanner->run();

        $results = $this->applySuppressions($results);

        // Apply --only / --skip filters
        if ($only = $this->option('only')) {
            $whitelist = array_map('strtolower', array_map('trim', explode(',', $only)));
            $results = array_filter(
                $results,
                fn ($name) => in_array(strtolower($name), $whitelist, true),
                ARRAY_FILTER_USE_KEY
            );
        }

        if ($skip = $this->option('skip')) {
            $blacklist = array_map('strtolower', array_map('trim', explode(',', $skip)));
            $results = array_filter(
                $results,
                fn ($name) => ! in_array(strtolower($name), $blacklist, true),
                ARRAY_FILTER_USE_KEY
            );
        }

        if ($this->option('json')) {
            return $this->outputJson($results);
        }

        return $this->outputTable($results);
    }

    /**
     * @param  array<string, CheckResult>  $results
     */
    private function outputTable(array $results): int
    {
        $passed = 0;
        $warned = 0;
        $failed = 0;

        foreach ($results as $name => $result) {
            match ($result->status) {
                CheckResult::PASS => $this->renderPass($name, $result),
                CheckResult::WARN => $this->renderWarn($name, $result),
                CheckResult::FAIL => $this->renderFail($name, $result),
            };

            match ($result->status) {
                CheckResult::PASS => $passed++,
                CheckResult::WARN => $warned++,
                CheckResult::FAIL => $failed++,
            };
        }

        $this->line('  ─────────────────────────────────────────────────────────');
        $this->line(sprintf(
            '  Summary  <fg=green>%d passed</>  <fg=yellow>%d warning(s)</>  <fg=red>%d failed</>  <fg=gray>(%d checks total)</>',
            $passed,
            $warned,
            $failed,
            $passed + $warned + $failed,
        ));
        $this->newLine();

        if ($failed > 0) {
            $this->line('  <fg=red;options=bold>Scan result: FAIL — fix the issues above before deploying.</>');
        } elseif ($warned > 0) {
            $this->line('  <fg=yellow;options=bold>Scan result: WARN — review the warnings above.</>');
        } else {
            $this->line('  <fg=green;options=bold>Scan result: PASS — no critical issues found.</>');
        }

        $this->newLine();

        return $failed > 0 ? Command::FAILURE : Command::SUCCESS;
    }

    /**
     * @param  array<string, CheckResult>  $results
     */
    private function outputJson(array $results): int
    {
        $payload = [];
        $exitCode = Command::SUCCESS;

        foreach ($results as $name => $result) {
            $hashes = array_map(
                fn ($detail) => $this->hashFinding($name, $detail),
                $result->details,
            );
            $payload[] = [
                'check' => $name,
                'status' => $result->status,
                'message' => $result->message,
                'details' => $result->details,
                'hashes' => $hashes,
            ];
            if ($result->status === CheckResult::FAIL) {
                $exitCode = Command::FAILURE;
            }
        }

        $this->line(json_encode($payload, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES));

        return $exitCode;
    }

    private function renderPass(string $name, CheckResult $result): void
    {
        $this->line("  <fg=green;options=bold>  PASS</>  <options=bold>{$name}</>");
        $this->line("        <fg=gray>{$result->message}</>");
        $this->newLine();
    }

    private function renderWarn(string $name, CheckResult $result): void
    {
        $this->line("  <fg=yellow;options=bold>  WARN</>  <options=bold>{$name}</>");
        $this->line("        <fg=yellow>{$result->message}</>");
        foreach ($result->details as $detail) {
            $hash = $this->hashFinding($name, $detail);
            $this->line("        <fg=gray>  ⚑ {$detail}</> <fg=blue>[{$hash}]</>");
        }
        $this->newLine();
    }

    private function renderFail(string $name, CheckResult $result): void
    {
        $this->line("  <fg=red;options=bold>  FAIL</>  <options=bold>{$name}</>");
        $this->line("        <fg=red>{$result->message}</>");
        foreach ($result->details as $detail) {
            $hash = $this->hashFinding($name, $detail);
            $this->line("        <fg=gray>  ✗ {$detail}</> <fg=blue>[{$hash}]</>");
        }
        $this->newLine();
    }

    /**
     * Compute a stable 12-char hash for a finding so users can suppress it
     * via config/checkpoint.php → 'suppressed'. Line numbers are stripped
     * from the detail before hashing so refactors that only shift lines
     * do not invalidate the suppression.
     */
    private function hashFinding(string $checkName, string $detail): string
    {
        $normalized = preg_replace('/:\d+(?=\s*[—-])/', '', $detail);

        return substr(sha1($checkName.'|'.$normalized), 0, 12);
    }

    /**
     * @param  array<string, CheckResult>  $results
     * @return array<string, CheckResult>
     */
    private function applySuppressions(array $results): array
    {
        $suppressed = array_flip((array) \config('checkpoint.suppressed', []));

        if (empty($suppressed)) {
            return $results;
        }

        $out = [];

        foreach ($results as $name => $result) {
            if ($result->status === CheckResult::PASS || empty($result->details)) {
                $out[$name] = $result;

                continue;
            }

            $kept = [];
            $skipped = 0;

            foreach ($result->details as $detail) {
                $hash = $this->hashFinding($name, $detail);
                if (isset($suppressed[$hash])) {
                    $skipped++;

                    continue;
                }
                $kept[] = $detail;
            }

            if ($skipped === 0) {
                $out[$name] = $result;

                continue;
            }

            if (empty($kept)) {
                $out[$name] = CheckResult::pass(
                    "All {$skipped} finding(s) suppressed via config."
                );

                continue;
            }

            $out[$name] = new CheckResult(
                $result->status,
                $result->message." ({$skipped} suppressed)",
                $kept,
            );
        }

        return $out;
    }
}
