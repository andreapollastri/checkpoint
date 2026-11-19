<?php

namespace Checkpoint\Tests\Unit\Checks;

use Checkpoint\Checks\CheckResult;
use Checkpoint\Checks\PhpCveCheck;
use Checkpoint\Tests\TestCase;

class PhpCveCheckTest extends TestCase
{
    private const DATABASE = [
        'generated' => '2026-11-16',
        'releases' => [
            '8.1' => [
                '8.1.34' => ['date' => '2025-12-18', 'advisories' => [
                    'CVE-2025-14178' => 'Standard: Heap buffer overflow in array_merge()',
                ]],
            ],
            '8.4' => [
                '8.4.1' => ['date' => '2024-11-21', 'advisories' => []],
                '8.4.24' => ['date' => '2026-07-30', 'advisories' => [
                    'CVE-2026-17543' => 'PGSQL: SQL injection via E\'...\' backslash breakout',
                ]],
                '8.4.26' => ['date' => '2026-09-24', 'advisories' => [
                    'CVE-2026-91768' => 'FPM: IPv6 ACL bypass in FastCGI listen.allowed_clients',
                    'CVE-2026-17545' => 'Windows: Reserved device names are not rejected before file and stream I/O',
                ]],
            ],
            '8.5' => [
                '8.5.9' => ['date' => '2026-07-30', 'advisories' => [
                    'CVE-2026-17543' => 'PGSQL: SQL injection via E\'...\' backslash breakout',
                ]],
            ],
        ],
    ];

    public function test_passes_on_the_latest_security_release(): void
    {
        $result = $this->check('8.4.26')->run();

        $this->assertSame(CheckResult::PASS, $result->status);
        $this->assertSame(
            'No known CVEs for PHP 8.4.26 (advisory database of 2026-11-16 + php.net release feed).',
            $result->message,
        );
    }

    public function test_fails_with_the_cves_fixed_in_newer_releases(): void
    {
        $result = $this->check('8.4.23')->run();

        $this->assertSame(CheckResult::FAIL, $result->status);
        $this->assertSame('PHP 8.4.23 is missing 2 security release(s) — upgrade to PHP 8.4.26 or later.', $result->message);
        $this->assertSame([
            'CVE-2026-91768 — FPM: IPv6 ACL bypass in FastCGI listen.allowed_clients (fixed in PHP 8.4.26)',
            'CVE-2026-17543 — PGSQL: SQL injection via E\'...\' backslash breakout (fixed in PHP 8.4.24)',
        ], $result->details);
    }

    public function test_windows_only_advisories_are_reported_on_windows(): void
    {
        $result = $this->check('8.4.25', os: 'Windows')->run();

        $this->assertSame(CheckResult::FAIL, $result->status);
        $this->assertCount(2, $result->details);
        $this->assertStringStartsWith('CVE-2026-17545 — Windows:', $result->details[1]);
    }

    public function test_security_release_without_published_ids_is_still_reported(): void
    {
        $result = $this->check('8.4.0')->run();

        $this->assertSame(CheckResult::FAIL, $result->status);
        $this->assertContains(
            'PHP 8.4.1 (2024-11-21) is a security release — see https://www.php.net/ChangeLog-8.php#8.4.1',
            $result->details,
        );
    }

    public function test_live_feed_catches_security_releases_newer_than_the_bundled_database(): void
    {
        $result = $this->check('8.4.26', feed: [
            '8.4.28' => ['date' => '2026-12-17', 'security' => false],
            '8.4.27' => ['date' => '2026-11-19', 'security' => true],
            '8.4.26' => ['date' => '2026-09-24', 'security' => true],
        ])->run();

        $this->assertSame(CheckResult::FAIL, $result->status);
        $this->assertSame('PHP 8.4.26 is missing 1 security release(s) — upgrade to PHP 8.4.27 or later.', $result->message);
        $this->assertSame(
            ['PHP 8.4.27 (2026-11-19) is a security release — see https://www.php.net/ChangeLog-8.php#8.4.27'],
            $result->details,
        );
    }

    public function test_warns_instead_of_passing_when_php_net_is_unreachable(): void
    {
        $result = $this->check('8.4.26', feed: null)->run();

        $this->assertSame(CheckResult::WARN, $result->status);
        $this->assertStringContainsString('php.net could not be reached', $result->message);
    }

    public function test_bundled_findings_still_fail_when_php_net_is_unreachable(): void
    {
        $result = $this->check('8.4.25', feed: null)->run();

        $this->assertSame(CheckResult::FAIL, $result->status);
        $this->assertCount(1, $result->details);
    }

    public function test_live_lookup_can_be_disabled(): void
    {
        $result = $this->check('8.4.26', feed: ['8.4.27' => ['date' => '2026-11-19', 'security' => true]], live: false)->run();

        $this->assertSame(CheckResult::PASS, $result->status);
        $this->assertStringContainsString('live lookup disabled', $result->message);
    }

    public function test_warns_for_pre_release_builds(): void
    {
        $result = $this->check('8.6.0RC5')->run();

        $this->assertSame(CheckResult::WARN, $result->status);
        $this->assertStringContainsString('PHP 8.6.0RC5 is a pre-release build', $result->message);
    }

    public function test_branches_newer_than_the_database_pass(): void
    {
        $result = $this->check('8.6.0')->run();

        $this->assertSame(CheckResult::PASS, $result->status);
    }

    public function test_end_of_life_branch_fails_even_on_its_last_release(): void
    {
        $result = $this->check('8.1.34')->run();

        $this->assertSame(CheckResult::FAIL, $result->status);
        $this->assertSame('PHP 8.1.34 is end-of-life and no longer receives security fixes — upgrade to a supported branch.', $result->message);
        $this->assertSame(
            ['PHP 8.1 has been end-of-life since 2025-12-31 — 3 advisories fixed in supported branches since then (latest: CVE-2026-91768, CVE-2026-17545, CVE-2026-17543) were not backported and may affect this build.'],
            $result->details,
        );
    }

    public function test_supported_branch_is_not_reported_as_end_of_life_before_its_cutoff(): void
    {
        $result = $this->check('8.1.34', today: '2025-12-20')->run();

        $this->assertSame(CheckResult::PASS, $result->status);
    }

    public function test_ubuntu_builds_warn_because_fixes_may_be_backported(): void
    {
        $result = $this->check('8.4.23-0ubuntu0.26.04.2')->run();

        $this->assertSame(CheckResult::WARN, $result->status);
        $this->assertStringContainsString('distribution build', $result->message);
        $this->assertCount(2, $result->details);
    }

    public function test_sury_builds_track_upstream_and_fail(): void
    {
        $result = $this->check('8.4.23-1+ubuntu24.04.1+deb.sury.org+1')->run();

        $this->assertSame(CheckResult::FAIL, $result->status);
    }

    public function test_suppression_hash_depends_on_the_advisory_id_only(): void
    {
        $result = $this->check('8.4.23')->run();

        $this->assertSame(
            CheckResult::hashFinding('PHP CVE Audit', 'CVE-2026-17543'),
            $result->hashFor('PHP CVE Audit', $result->details[1]),
        );
    }

    public function test_warns_when_the_version_cannot_be_parsed(): void
    {
        $result = $this->check('nightly')->run();

        $this->assertSame(CheckResult::WARN, $result->status);
    }

    public function test_bundled_database_is_well_formed(): void
    {
        $database = require __DIR__.'/../../../resources/php-advisories.php';

        $this->assertMatchesRegularExpression('/^\d{4}-\d{2}-\d{2}$/', $database['generated']);
        $this->assertNotEmpty($database['releases']);

        foreach ($database['releases'] as $branch => $releases) {
            $this->assertSame($releases, $this->sortedByVersion($releases), "PHP {$branch} releases are not sorted.");

            foreach ($releases as $version => $release) {
                $this->assertStringStartsWith("{$branch}.", $version);
                $this->assertMatchesRegularExpression('/^\d{4}-\d{2}-\d{2}$/', $release['date'], "PHP {$version} has no release date.");

                foreach ($release['advisories'] as $id => $summary) {
                    $this->assertMatchesRegularExpression('/^(?:CVE-\d{4}-\d+|GHSA-[0-9a-z]{4}-[0-9a-z]{4}-[0-9a-z]{4}(?: \/ GHSA-[0-9a-z]{4}-[0-9a-z]{4}-[0-9a-z]{4})*)$/', $id);
                    $this->assertMatchesRegularExpression('/^[^:]+: \S/', $summary, "{$id} has no \"Component: summary\".");
                }
            }
        }
    }

    public function test_bundled_database_knows_the_php_cgi_argument_injection(): void
    {
        $result = (new PhpCveCheck(false, '8.3.7', osFamily: 'Linux'))->run();

        $this->assertSame(CheckResult::FAIL, $result->status);
        $this->assertContains(
            'CVE-2024-4577 — CGI: Bypass of CVE-2012-1823, Argument Injection in PHP-CGI (fixed in PHP 8.3.8)',
            $result->details,
        );
    }

    /**
     * @param  array<string, array{date: string, security: bool}>|null  $feed  What php.net answers; null = unreachable.
     */
    private function check(
        string $php,
        ?array $feed = [],
        bool $live = true,
        string $today = '2026-11-16',
        string $os = 'Linux',
    ): PhpCveCheck {
        $now = (int) strtotime($today.' 12:00:00 UTC');

        return new class($live, $php, $now, $os, self::DATABASE, $feed) extends PhpCveCheck
        {
            public function __construct(bool $live, string $php, int $now, string $os, array $database, private ?array $feed)
            {
                parent::__construct($live, $php, $now, $os, $database);
            }

            protected function fetchReleases(string $branch): ?array
            {
                return $this->feed;
            }
        };
    }

    /**
     * @param  array<string, mixed>  $releases
     * @return array<string, mixed>
     */
    private function sortedByVersion(array $releases): array
    {
        uksort($releases, 'version_compare');

        return $releases;
    }
}
