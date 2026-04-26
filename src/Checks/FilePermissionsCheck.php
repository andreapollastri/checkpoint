<?php

namespace Checkpoint\Checks;

class FilePermissionsCheck extends AbstractCheck
{
    public function __construct(private readonly string $basePath) {}

    public function name(): string
    {
        return 'File Permissions';
    }

    public function run(): CheckResult
    {
        $issues = [];

        $envPath = $this->basePath.'/.env';
        if (file_exists($envPath)) {
            $perms = fileperms($envPath) & 0777;
            // World-readable or group-writable are both bad
            if ($perms & 0004) {
                $issues[] = '.env is world-readable (perms: '.decoct($perms).') — restrict to 600 or 640.';
            }
            if ($perms & 0002) {
                $issues[] = '.env is world-writable (perms: '.decoct($perms).') — restrict immediately.';
            }
        }

        $storagePath = $this->basePath.'/storage';
        if (is_dir($storagePath)) {
            $perms = fileperms($storagePath) & 0777;
            if ($perms & 0002) {
                $issues[] = 'storage/ is world-writable (perms: '.decoct($perms).') — restrict to 775.';
            }
        }

        if (empty($issues)) {
            return CheckResult::pass('File permissions look appropriate.');
        }

        return CheckResult::warn(count($issues).' file permission issue(s) found.', $issues);
    }
}
