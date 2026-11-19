<?php

namespace Checkpoint\Checks;

use Symfony\Component\Finder\Finder;

class PublicExposureCheck extends AbstractCheck
{
    private const PHP_EXTENSIONS = '/\.(?:php\d?|phtml|pht|phar)$/i';

    private const DATABASE_DUMPS = '/\.(?:sql|dump|bak|backup|sqlite3?|db)(?:\.(?:gz|zip|bz2|xz))?$/i';

    private const BACKUP_ARCHIVES = '/(?:backup|dump|database|public_html|htdocs)[^\/]*\.(?:zip|tar|tgz|tar\.gz|7z|rar)$/i';

    private const ADMIN_TOOLS = '/^(?:adminer|phpmyadmin|pma)\b/i';

    public function __construct(private readonly string $basePath) {}

    public function name(): string
    {
        return 'Public Directory Exposure';
    }

    public function run(): CheckResult
    {
        $failures = [];
        $warnings = [];

        // ---- The web root must be public/, never the project root ----
        foreach (['index.php', '.htaccess'] as $file) {
            if (is_file($this->basePath.'/'.$file)) {
                $warnings[] = "{$file} — found in the project root. If the web server serves this directory instead of public/, then .env, vendor/ and storage/ are downloadable.";
            }
        }

        // ---- Files anyone can request from public/ ----
        $public = $this->basePath.'/public';

        if (is_dir($public)) {
            if (file_exists($public.'/.git')) {
                $failures[] = 'public/.git — repository metadata is downloadable (source code and history disclosure).';
            }

            foreach ($this->files($public) as $file) {
                $relative = 'public/'.str_replace('\\', '/', $file->getRelativePathname());
                $name = $file->getFilename();
                $topLevel = explode('/', $relative)[1];

                if (preg_match(self::ADMIN_TOOLS, $topLevel)) {
                    $failures["tool:{$topLevel}"] = "public/{$topLevel} — database administration tool reachable from the internet. Remove it or move it behind a VPN.";
                } elseif (preg_match('/^\.env(?:\..+)?$/', $name) && $name !== '.env.example') {
                    $failures[] = "{$relative} — environment file is downloadable by anyone.";
                } elseif (preg_match(self::DATABASE_DUMPS, $name) && strtolower($name) !== 'thumbs.db') {
                    $failures[] = "{$relative} — database dump / backup is downloadable by anyone.";
                } elseif (preg_match(self::BACKUP_ARCHIVES, $name)) {
                    $warnings[] = "{$relative} — looks like a backup archive; anything under public/ is downloadable.";
                } elseif (preg_match(self::PHP_EXTENSIONS, $name)) {
                    if (preg_match('/\bphpinfo\s*\(/', $file->getContents())) {
                        $failures[] = "{$relative} — calls phpinfo(): exposes the full PHP configuration, environment variables and secrets.";
                    } elseif ($relative !== 'public/index.php') {
                        $warnings[] = "{$relative} — unexpected PHP entry point. Only public/index.php should be executable: verify it is not a leftover script or a webshell.";
                    }
                }
            }
        }

        // ---- Uploads must never be executable ----
        $uploads = $this->basePath.'/storage/app/public';

        if (is_dir($uploads)) {
            foreach ($this->files($uploads) as $file) {
                if (preg_match(self::PHP_EXTENSIONS, $file->getFilename())) {
                    $failures[] = 'storage/app/public/'.str_replace('\\', '/', $file->getRelativePathname())
                        .' — PHP file in the public storage disk. Uploads must never be executable: possible webshell or unrestricted file upload.';
                }
            }
        }

        $failures = array_values($failures);

        if ($failures === [] && $warnings === []) {
            return CheckResult::pass('No sensitive or unexpected files exposed through public/.');
        }

        $details = array_merge($failures, $warnings);
        $message = count($details).' publicly exposed file(s) found.';

        return $failures !== []
            ? CheckResult::fail($message, $details)
            : CheckResult::warn($message, $details);
    }

    private function files(string $directory): Finder
    {
        return (new Finder())
            ->files()
            ->in($directory)
            ->ignoreDotFiles(false)
            ->ignoreUnreadableDirs()
            ->sortByName();
    }
}
