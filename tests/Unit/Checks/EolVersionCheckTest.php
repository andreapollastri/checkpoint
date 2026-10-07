<?php

namespace Checkpoint\Tests\Unit\Checks;

use Checkpoint\Checks\CheckResult;
use Checkpoint\Checks\EolVersionCheck;
use Checkpoint\Tests\TestCase;

class EolVersionCheckTest extends TestCase
{
    public function test_passes_for_supported_versions(): void
    {
        $result = $this->check('8.4.12', '13.35.0', '2026-10-07')->run();

        $this->assertSame(CheckResult::PASS, $result->status);
    }

    public function test_fails_for_php_past_its_security_eol(): void
    {
        $result = $this->check('8.1.33', null, '2026-10-07')->run();

        $this->assertSame(CheckResult::FAIL, $result->status);
        $this->assertSame(
            ['PHP 8.1.33 is end-of-life since 2025-12-31 — no security fixes from upstream. Upgrade to PHP 8.3+ as soon as possible.'],
            $result->details,
        );
    }

    public function test_fails_for_php_branches_older_than_the_table(): void
    {
        $result = $this->check('7.4.33', null, '2026-10-07')->run();

        $this->assertSame(CheckResult::FAIL, $result->status);
        $this->assertStringContainsString('PHP 7.4.33 is end-of-life —', $result->details[0]);
    }

    public function test_warns_when_php_security_support_ends_within_a_year(): void
    {
        $result = $this->check('8.2.29', null, '2026-10-07')->run();

        $this->assertSame(CheckResult::WARN, $result->status);
        $this->assertSame(
            ['PHP 8.2.29 receives security fixes only until 2026-12-31. Plan an upgrade to PHP 8.3+.'],
            $result->details,
        );
    }

    public function test_laravel_11_is_eol_after_march_2026(): void
    {
        $before = $this->check('8.4.0', 'v11.45.0', '2026-03-12')->run();
        $after = $this->check('8.4.0', 'v11.45.0', '2026-03-13')->run();

        $this->assertSame(CheckResult::WARN, $before->status);
        $this->assertSame(CheckResult::FAIL, $after->status);
        $this->assertSame(
            ['Laravel 11.45.0 is end-of-life since 2026-03-12 — no security fixes. Upgrade to Laravel 13+ as soon as possible.'],
            $after->details,
        );
    }

    public function test_warns_for_laravel_12_within_a_year_of_its_eol(): void
    {
        $result = $this->check('8.4.0', '12.31.1', '2026-10-07')->run();

        $this->assertSame(CheckResult::WARN, $result->status);
        $this->assertStringContainsString('until 2027-02-24', $result->details[0]);
    }

    public function test_unknown_future_branches_are_treated_as_supported(): void
    {
        $result = $this->check('9.0.0', '14.0.0', '2026-10-07')->run();

        $this->assertSame(CheckResult::PASS, $result->status);
    }

    public function test_reports_both_php_and_laravel(): void
    {
        $result = $this->check('8.0.30', '9.52.16', '2026-10-07')->run();

        $this->assertSame(CheckResult::FAIL, $result->status);
        $this->assertCount(2, $result->details);
    }

    private function check(string $php, ?string $laravel, string $today): EolVersionCheck
    {
        $workspace = $this->makeWorkspace();

        if ($laravel !== null) {
            $this->writeFile($workspace, 'composer.lock', json_encode([
                'packages' => [['name' => 'laravel/framework', 'version' => $laravel]],
                'packages-dev' => [],
            ], JSON_THROW_ON_ERROR));
        }

        return new EolVersionCheck($workspace, $php, (int) strtotime($today.' 12:00:00 UTC'));
    }
}
