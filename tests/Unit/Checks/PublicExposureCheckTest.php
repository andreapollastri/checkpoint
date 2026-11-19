<?php

namespace Checkpoint\Tests\Unit\Checks;

use Checkpoint\Checks\CheckResult;
use Checkpoint\Checks\PublicExposureCheck;
use Checkpoint\Tests\TestCase;

class PublicExposureCheckTest extends TestCase
{
    public function test_passes_on_a_stock_laravel_skeleton(): void
    {
        $workspace = $this->skeleton();

        $result = (new PublicExposureCheck($workspace))->run();

        $this->assertSame(CheckResult::PASS, $result->status);
    }

    public function test_passes_without_a_public_directory(): void
    {
        $result = (new PublicExposureCheck($this->makeWorkspace()))->run();

        $this->assertSame(CheckResult::PASS, $result->status);
    }

    public function test_fails_on_sensitive_files_under_public(): void
    {
        $workspace = $this->skeleton();
        $this->writeFile($workspace, 'public/.env', "APP_KEY=base64:abc\n");
        $this->writeFile($workspace, 'public/.git/HEAD', "ref: refs/heads/main\n");
        $this->writeFile($workspace, 'public/adminer.php', "<?php // adminer\n");
        $this->writeFile($workspace, 'public/downloads/dump.sql.gz', 'x');
        $this->writeFile($workspace, 'public/info.php', "<?php phpinfo();\n");
        $this->writeFile($workspace, 'public/phpMyAdmin/index.php', "<?php\n");
        $this->writeFile($workspace, 'public/phpMyAdmin/libraries/common.php', "<?php\n");

        $result = (new PublicExposureCheck($workspace))->run();

        $this->assertSame(CheckResult::FAIL, $result->status);
        $this->assertSame([
            'public/.git — repository metadata is downloadable (source code and history disclosure).',
            'public/.env — environment file is downloadable by anyone.',
            'public/adminer.php — database administration tool reachable from the internet. Remove it or move it behind a VPN.',
            'public/downloads/dump.sql.gz — database dump / backup is downloadable by anyone.',
            'public/info.php — calls phpinfo(): exposes the full PHP configuration, environment variables and secrets.',
            'public/phpMyAdmin — database administration tool reachable from the internet. Remove it or move it behind a VPN.',
        ], $result->details);
    }

    public function test_warns_on_stray_php_files_and_backup_archives(): void
    {
        $workspace = $this->skeleton();
        $this->writeFile($workspace, 'public/old/test.php', "<?php echo 'hi';\n");
        $this->writeFile($workspace, 'public/site-backup-2026.zip', 'x');

        $result = (new PublicExposureCheck($workspace))->run();

        $this->assertSame(CheckResult::WARN, $result->status);
        $this->assertCount(2, $result->details);
        $this->assertStringStartsWith('public/old/test.php — unexpected PHP entry point', $result->details[0]);
        $this->assertStringStartsWith('public/site-backup-2026.zip — looks like a backup archive', $result->details[1]);
    }

    public function test_warns_when_the_project_root_looks_web_served(): void
    {
        $workspace = $this->skeleton();
        $this->writeFile($workspace, 'index.php', "<?php require 'public/index.php';\n");
        $this->writeFile($workspace, '.htaccess', "RewriteRule ^(.*)$ public/$1 [L]\n");

        $result = (new PublicExposureCheck($workspace))->run();

        $this->assertSame(CheckResult::WARN, $result->status);
        $this->assertCount(2, $result->details);
        $this->assertStringStartsWith('index.php — found in the project root', $result->details[0]);
    }

    public function test_fails_on_executable_files_in_the_public_storage_disk(): void
    {
        $workspace = $this->skeleton();
        $this->writeFile($workspace, 'storage/app/public/avatars/shell.phtml', "<?php system(\$_GET['c']);\n");
        $this->writeFile($workspace, 'storage/app/public/avatars/me.png', 'x');

        $result = (new PublicExposureCheck($workspace))->run();

        $this->assertSame(CheckResult::FAIL, $result->status);
        $this->assertCount(1, $result->details);
        $this->assertStringStartsWith('storage/app/public/avatars/shell.phtml — PHP file in the public storage disk', $result->details[0]);
    }

    public function test_ignores_harmless_lookalikes(): void
    {
        $workspace = $this->skeleton();
        $this->writeFile($workspace, 'public/.env.example', "APP_KEY=\n");
        $this->writeFile($workspace, 'public/img/Thumbs.db', 'x');
        $this->writeFile($workspace, 'public/downloads/brochure.zip', 'x');
        $this->writeFile($workspace, 'public/build/assets/app.js', 'phpinfo()');

        $result = (new PublicExposureCheck($workspace))->run();

        $this->assertSame(CheckResult::PASS, $result->status);
    }

    private function skeleton(): string
    {
        $workspace = $this->makeWorkspace();
        $this->writeFile($workspace, 'public/index.php', "<?php require __DIR__.'/../vendor/autoload.php';\n");
        $this->writeFile($workspace, 'public/.htaccess', "RewriteEngine On\n");
        $this->writeFile($workspace, 'public/robots.txt', "User-agent: *\n");
        $this->writeFile($workspace, 'storage/app/public/.gitignore', "*\n!.gitignore\n");

        return $workspace;
    }
}
