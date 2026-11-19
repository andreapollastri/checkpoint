<?php

namespace Checkpoint\Tests\Unit\Checks;

use Checkpoint\Checks\CheckResult;
use Checkpoint\Checks\PhpIniCheck;
use Checkpoint\Tests\TestCase;

class PhpIniCheckTest extends TestCase
{
    /** Effective directives of a hardened process, as ini_get() reports them. */
    private const HARDENED = [
        'allow_url_include' => '0',
        'display_errors' => '',
        'display_startup_errors' => '',
        'expose_php' => '',
        'zend.exception_ignore_args' => '1',
        'error_include_args' => '0',
        'auto_prepend_file' => '',
        'auto_append_file' => '',
    ];

    public function test_passes_with_a_hardened_runtime(): void
    {
        $result = $this->check(self::HARDENED)->run();

        $this->assertSame(CheckResult::PASS, $result->status);
        $this->assertSame('PHP configuration looks hardened (checked: runtime (cli)).', $result->message);
    }

    public function test_fails_when_remote_includes_are_allowed(): void
    {
        $result = $this->check(['allow_url_include' => '1', 'expose_php' => '1'] + self::HARDENED)->run();

        $this->assertSame(CheckResult::FAIL, $result->status);
        $this->assertCount(2, $result->details);
        $this->assertStringStartsWith('runtime (cli): allow_url_include = On', $result->details[0]);
        $this->assertStringContainsString('CVE-2024-4577', $result->details[0]);
        $this->assertStringStartsWith('runtime (cli): expose_php = On', $result->details[1]);
    }

    public function test_warns_on_every_information_leaking_directive(): void
    {
        $result = $this->check([
            'display_errors' => 'stdout',
            'display_startup_errors' => '1',
            'expose_php' => '1',
            'zend.exception_ignore_args' => '0',
            'error_include_args' => '1',
        ] + self::HARDENED)->run();

        $this->assertSame(CheckResult::WARN, $result->status);
        $this->assertSame('5 PHP configuration issue(s) found.', $result->message);
    }

    public function test_display_errors_to_stderr_is_not_shown_to_visitors(): void
    {
        $result = $this->check(['display_errors' => 'stderr'] + self::HARDENED)->run();

        $this->assertSame(CheckResult::PASS, $result->status);
    }

    public function test_warns_on_auto_prepend_file_but_not_on_known_dev_tools(): void
    {
        $shell = $this->check(['auto_prepend_file' => '/var/www/.cache.php'] + self::HARDENED)->run();
        $herd = $this->check(['auto_prepend_file' => '/Applications/Herd.app/Contents/Resources/valet/dump-loader.php'] + self::HARDENED)->run();

        $this->assertSame(CheckResult::WARN, $shell->status);
        $this->assertStringContainsString('auto_prepend_file = "/var/www/.cache.php"', $shell->details[0]);
        $this->assertSame(CheckResult::PASS, $herd->status);
    }

    public function test_warns_when_xdebug_is_active(): void
    {
        $active = $this->check(['xdebug.mode' => 'develop,debug', 'xdebug.discover_client_host' => '1'] + self::HARDENED)->run();
        $off = $this->check(['xdebug.mode' => 'off'] + self::HARDENED)->run();

        $this->assertSame(CheckResult::WARN, $active->status);
        $this->assertCount(2, $active->details);
        $this->assertSame(CheckResult::PASS, $off->status);
    }

    public function test_warns_when_cgi_force_redirect_is_disabled(): void
    {
        $result = $this->check(['cgi.force_redirect' => '0'] + self::HARDENED)->run();

        $this->assertSame(CheckResult::WARN, $result->status);
        $this->assertStringContainsString('CVE-2024-8927', $result->details[0]);
    }

    public function test_audits_the_web_sapi_php_ini_next_to_the_cli_one(): void
    {
        $workspace = $this->makeWorkspace();
        $cli = $this->writeFile($workspace, 'etc/php/8.6/cli/php.ini', "display_errors = Off\n");
        $fpm = $this->writeFile($workspace, 'etc/php/8.6/fpm/php.ini', implode("\n", [
            '[PHP]',
            'error_reporting = E_ALL & ~E_DEPRECATED',
            'display_errors = On ; overridden in conf.d',
            'expose_php = On',
            'allow_url_include = "On"',
        ]));
        $this->writeFile($workspace, 'etc/php/8.6/fpm/conf.d/20-xdebug.ini', "zend_extension=xdebug.so\n");
        $this->writeFile($workspace, 'etc/php/8.6/fpm/conf.d/99-production.ini', "display_errors = Off\n");

        $result = (new PhpIniCheck($workspace, [], self::HARDENED, $cli))->run();

        $this->assertSame(CheckResult::FAIL, $result->status);
        $this->assertCount(3, $result->details);
        $this->assertStringStartsWith("{$fpm}: allow_url_include = On", $result->details[0]);
        $this->assertStringStartsWith("{$fpm}: expose_php = On", $result->details[1]);
        $this->assertStringStartsWith("{$fpm}: xdebug.mode = develop", $result->details[2]);
    }

    public function test_ini_files_are_only_judged_on_directives_they_set(): void
    {
        $workspace = $this->makeWorkspace();
        $cli = $this->writeFile($workspace, 'etc/php/8.6/cli/php.ini', '');
        $fpm = $this->writeFile($workspace, 'etc/php/8.6/fpm/php.ini', "memory_limit = 256M\n");

        $result = (new PhpIniCheck($workspace, [], self::HARDENED, $cli))->run();

        $this->assertSame(CheckResult::PASS, $result->status);
        $this->assertStringContainsString($fpm, $result->message);
    }

    public function test_audits_a_user_ini_in_the_web_root(): void
    {
        $workspace = $this->makeWorkspace();
        $this->writeFile($workspace, 'public/.user.ini', "auto_prepend_file = /tmp/x.php\n");

        $result = (new PhpIniCheck($workspace, [], self::HARDENED, ''))->run();

        $this->assertSame(CheckResult::WARN, $result->status);
        $this->assertStringStartsWith('public/.user.ini: auto_prepend_file = "/tmp/x.php"', $result->details[0]);
    }

    public function test_audits_files_listed_in_config(): void
    {
        $workspace = $this->makeWorkspace();
        $this->writeFile($workspace, 'docker/php/php.ini', "expose_php = On\n");
        $this->writeFile($workspace, 'docker/php/conf.d/app.ini', "display_errors = 1\n");

        $result = (new PhpIniCheck($workspace, ['docker/php/php.ini', 'docker/php/conf.d'], self::HARDENED, ''))->run();

        $this->assertSame(CheckResult::WARN, $result->status);
        $this->assertCount(2, $result->details);
        $this->assertStringStartsWith('docker/php/php.ini: expose_php = On', $result->details[0]);
        $this->assertStringStartsWith('docker/php/conf.d: display_errors = On', $result->details[1]);
    }

    public function test_warns_when_a_configured_file_cannot_be_read(): void
    {
        $result = (new PhpIniCheck($this->makeWorkspace(), ['/nonexistent/php.ini'], self::HARDENED, ''))->run();

        $this->assertSame(CheckResult::WARN, $result->status);
        $this->assertSame(
            ['/nonexistent/php.ini: listed in `php_ini.files` but could not be read — this configuration was not audited.'],
            $result->details,
        );
    }

    public function test_reads_the_real_runtime_without_errors(): void
    {
        $result = (new PhpIniCheck($this->makeWorkspace()))->run();

        $this->assertContains($result->status, [CheckResult::PASS, CheckResult::WARN, CheckResult::FAIL]);
    }

    /**
     * @param  array<string, string>  $runtime
     */
    private function check(array $runtime): PhpIniCheck
    {
        return new PhpIniCheck($this->makeWorkspace(), [], $runtime, '');
    }
}
