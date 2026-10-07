<?php

namespace Checkpoint\Tests\Unit\Checks;

use Checkpoint\Checks\CheckResult;
use Checkpoint\Checks\ComposerConfigCheck;
use Checkpoint\Tests\TestCase;

class ComposerConfigCheckTest extends TestCase
{
    public function test_warns_when_composer_json_is_missing(): void
    {
        $workspace = $this->makeWorkspace();

        $result = (new ComposerConfigCheck($workspace))->run();

        $this->assertSame(CheckResult::WARN, $result->status);
        $this->assertStringContainsString('composer.json not found', $result->message);
    }

    public function test_passes_on_a_default_laravel_manifest(): void
    {
        $result = $this->scan([
            'require' => ['laravel/framework' => '^13.0'],
            'config' => [
                'optimize-autoloader' => true,
                'allow-plugins' => ['pestphp/pest-plugin' => true, 'php-http/discovery' => true],
            ],
            'minimum-stability' => 'stable',
            'prefer-stable' => true,
        ]);

        $this->assertSame(CheckResult::PASS, $result->status);
    }

    public function test_fails_when_secure_http_or_tls_is_disabled(): void
    {
        $result = $this->scan(['config' => ['secure-http' => false, 'disable-tls' => true]]);

        $this->assertSame(CheckResult::FAIL, $result->status);
        $this->assertCount(2, $result->details);
        $this->assertStringContainsString('config.secure-http is false', $result->details[0]);
        $this->assertStringContainsString('config.disable-tls is true', $result->details[1]);
    }

    public function test_fails_on_plain_http_repositories_in_list_and_map_form(): void
    {
        $list = $this->scan(['repositories' => [
            ['type' => 'composer', 'url' => 'http://packages.example.com'],
            ['type' => 'vcs', 'url' => 'https://github.com/acme/lib'],
        ]]);
        $map = $this->scan(['repositories' => [
            'private' => ['type' => 'composer', 'url' => 'HTTP://satis.local'],
            'packagist.org' => false,
        ]]);

        $this->assertSame(CheckResult::FAIL, $list->status);
        $this->assertSame(['repositories: http://packages.example.com uses plain HTTP — packages can be tampered with in transit.'], $list->details);
        $this->assertSame(CheckResult::FAIL, $map->status);
        $this->assertCount(1, $map->details);
    }

    public function test_fails_on_credentials_without_leaking_them(): void
    {
        $result = $this->scan(['config' => [
            'github-oauth' => ['github.com' => 'ghp_supersecretvalue'],
            'http-basic' => ['repo.example.com' => ['username' => 'u', 'password' => 'p4ss']],
        ]]);

        $this->assertSame(CheckResult::FAIL, $result->status);
        $this->assertCount(2, $result->details);
        $this->assertStringNotContainsString('ghp_supersecretvalue', implode("\n", $result->details));
        $this->assertStringNotContainsString('p4ss', implode("\n", $result->details));
    }

    public function test_warns_when_every_plugin_is_allowed(): void
    {
        $result = $this->scan(['config' => ['allow-plugins' => true]]);

        $this->assertSame(CheckResult::WARN, $result->status);
        $this->assertStringContainsString('config.allow-plugins is true', $result->details[0]);
    }

    public function test_warns_on_unstable_minimum_stability_without_prefer_stable(): void
    {
        $risky = $this->scan(['minimum-stability' => 'dev']);
        $safe = $this->scan(['minimum-stability' => 'dev', 'prefer-stable' => true]);

        $this->assertSame(CheckResult::WARN, $risky->status);
        $this->assertStringContainsString('minimum-stability is "dev"', $risky->details[0]);
        $this->assertSame(CheckResult::PASS, $safe->status);
    }

    public function test_warns_when_audit_blocking_is_disabled(): void
    {
        $result = $this->scan(['config' => ['audit' => ['block-insecure' => false]]]);

        $this->assertSame(CheckResult::WARN, $result->status);
        $this->assertStringContainsString('block-insecure is false', $result->details[0]);
    }

    public function test_lists_ignored_advisories_in_list_and_map_form(): void
    {
        $list = $this->scan(['config' => ['audit' => ['ignore' => ['CVE-2026-0001', 'GHSA-xxxx-yyyy-zzzz']]]]);
        $map = $this->scan(['config' => ['audit' => ['ignore' => ['PKSA-abcd' => 'Not reachable from our code']]]]);

        $this->assertSame(CheckResult::WARN, $list->status);
        $this->assertStringContainsString('silences 2 advisory(ies)', $list->details[0]);
        $this->assertStringContainsString('CVE-2026-0001, GHSA-xxxx-yyyy-zzzz', $list->details[0]);
        $this->assertStringContainsString('PKSA-abcd', $map->details[0]);
    }

    /**
     * @param  array<string, mixed>  $manifest
     */
    private function scan(array $manifest): CheckResult
    {
        $workspace = $this->makeWorkspace();
        $this->writeFile($workspace, 'composer.json', json_encode($manifest, JSON_THROW_ON_ERROR));

        return (new ComposerConfigCheck($workspace))->run();
    }
}
