<?php

namespace Checkpoint\Checks;

class PhpCveCheck extends AbstractCheck
{
    private const DATABASE = __DIR__.'/../../resources/php-advisories.php';

    private const FEED_URL = 'https://www.php.net/releases/index.php?json&max=500&version=';

    private const FEED_TIMEOUT = 5;

    /**
     * @param  bool  $liveLookup  Ask php.net for security releases newer than the bundled database.
     * @param  array{generated: string, releases: array<string, array<string, array{date: string, advisories: array<string, string>}>>}|null  $database
     */
    public function __construct(
        private readonly bool $liveLookup = true,
        private readonly ?string $phpVersion = null,
        private readonly ?int $now = null,
        private readonly ?string $osFamily = null,
        private readonly ?array $database = null,
    ) {}

    public function name(): string
    {
        return 'PHP CVE Audit';
    }

    public function run(): CheckResult
    {
        $php = $this->phpVersion ?? PHP_VERSION;

        if (! preg_match('/^(\d+\.\d+)\.(\d+)(.*)$/', $php, $m)) {
            return CheckResult::warn("Could not parse the PHP version \"{$php}\" — its CVE status is unknown.");
        }

        [$branch, $running, $extra] = [$m[1], "{$m[1]}.{$m[2]}", $m[3]];

        $database = $this->database ?? require self::DATABASE;
        $bundled = $database['releases'][$branch] ?? [];

        $details = [];
        $hashes = [];
        $missing = [];

        $report = function (string $key, string $detail, ?string $release = null) use (&$details, &$hashes, &$missing): void {
            $details[] = $detail;
            $hashes[$detail] = CheckResult::hashFinding($this->name(), $key);

            if ($release !== null) {
                $missing[$release] = true;
            }
        };

        // ---- Security releases php.net knows about but the bundled database does not ----
        $feed = $this->liveLookup ? $this->fetchReleases($branch) : [];

        foreach ($this->newestFirst($feed ?? []) as $release => $info) {
            if ($info['security'] && ! isset($bundled[$release]) && version_compare($release, $running, '>')) {
                $report("PHP {$release}", $this->describeRelease($release, $info['date']), $release);
            }
        }

        // ---- Advisories fixed in releases newer than the running one ----
        foreach ($this->newestFirst($bundled) as $release => $info) {
            if (version_compare($release, $running, '<=')) {
                continue;
            }

            if ($info['advisories'] === []) {
                $report("PHP {$release}", $this->describeRelease($release, $info['date']), $release);
            }

            foreach ($info['advisories'] as $id => $summary) {
                if (str_starts_with($summary, 'Windows:') && ($this->osFamily ?? PHP_OS_FAMILY) !== 'Windows') {
                    continue;
                }

                $report($id, "{$id} — {$summary} (fixed in PHP {$release})", $release);
            }
        }

        // ---- End-of-life branch: later advisories were never backported ----
        $unpatched = $this->unpatchedSinceEol($database['releases'], $branch);

        if ($unpatched !== null && $unpatched['ids'] !== []) {
            $report("PHP {$branch} end-of-life", sprintf(
                'PHP %s has been end-of-life since %s — %d advisories fixed in supported branches since then (latest: %s) were not backported and may affect this build.',
                $branch,
                $unpatched['since'],
                count($unpatched['ids']),
                implode(', ', array_slice($unpatched['ids'], 0, 3)),
            ));
        }

        if ($details === []) {
            return $this->clean($php, $extra, $database['generated'], $feed === null);
        }

        $message = $missing === []
            ? "PHP {$php} is end-of-life and no longer receives security fixes — upgrade to a supported branch."
            : sprintf(
                'PHP %s is missing %d security release(s) — upgrade to PHP %s or later.',
                $php,
                count($missing),
                array_key_first($this->newestFirst($missing)),
            );

        // Ubuntu backports security fixes without bumping the upstream version,
        // so the version number alone cannot prove a distro build is vulnerable.
        if (preg_match('/ubuntu/i', $extra) && ! preg_match('/sury/i', $extra)) {
            return CheckResult::warn(
                $message.' This is a distribution build: fixes may have been backported, verify with your distro\'s security tracker.',
                $details,
                $hashes,
            );
        }

        return CheckResult::fail($message, $details, $hashes);
    }

    /**
     * Releases of a PHP branch as published by php.net.
     *
     * @return array<string, array{date: string, security: bool}>|null  null when php.net could not be reached.
     */
    protected function fetchReleases(string $branch): ?array
    {
        $context = stream_context_create(['http' => [
            'timeout' => self::FEED_TIMEOUT,
            'ignore_errors' => true,
            'user_agent' => 'andreapollastri/checkpoint',
        ]]);

        $body = @file_get_contents(self::FEED_URL.$branch, false, $context);
        $feed = is_string($body) ? json_decode($body, true) : null;

        if (! is_array($feed)) {
            return null;
        }

        // php.net answers {"error": "Unknown version"} for a branch without a stable release yet.
        if (isset($feed['error'])) {
            return [];
        }

        $releases = [];

        foreach ($feed as $version => $release) {
            if (! is_array($release)) {
                continue;
            }

            $timestamp = strtotime((string) ($release['date'] ?? ''));

            $releases[(string) $version] = [
                'date' => $timestamp !== false ? gmdate('Y-m-d', $timestamp) : '',
                'security' => in_array('security', (array) ($release['tags'] ?? []), true),
            ];
        }

        return $releases;
    }

    private function clean(string $php, string $extra, string $generated, bool $feedUnreachable): CheckResult
    {
        if (preg_match('/^-?(?:alpha|beta|rc|dev)/i', $extra)) {
            return CheckResult::warn("PHP {$php} is a pre-release build — pre-releases are not covered by security advisories. Run a stable release in production.");
        }

        if ($feedUnreachable) {
            return CheckResult::warn(
                "No known CVEs for PHP {$php} in the bundled advisory database ({$generated}), but php.net could not be reached to check for newer security releases.",
                ['Allow outbound HTTPS to www.php.net, or set `php_cve.live_lookup` to false in config/checkpoint.php to rely on the bundled database only.'],
            );
        }

        $source = $this->liveLookup
            ? "advisory database of {$generated} + php.net release feed"
            : "bundled advisory database of {$generated}, live lookup disabled";

        return CheckResult::pass("No known CVEs for PHP {$php} ({$source}).");
    }

    private function describeRelease(string $release, string $date): string
    {
        $published = $date !== '' ? " ({$date})" : '';

        return "PHP {$release}{$published} is a security release — see https://www.php.net/ChangeLog-".((int) $release).".php#{$release}";
    }

    /**
     * Advisories fixed in newer branches after this branch stopped receiving fixes.
     *
     * @param  array<string, array<string, array{date: string, advisories: array<string, string>}>>  $releases
     * @return array{since: string, ids: list<string>}|null  null when the branch is still supported.
     */
    private function unpatchedSinceEol(array $releases, string $branch): ?array
    {
        $eol = EolVersionCheck::PHP_SECURITY_EOL[$branch] ?? null;

        if ($eol === null || ($this->now ?? time()) <= (int) strtotime($eol.' 23:59:59 UTC')) {
            return null;
        }

        $ids = [];

        foreach ($releases as $other => $versions) {
            if (version_compare((string) $other, $branch, '<=')) {
                continue;
            }

            foreach ($versions as $info) {
                if ($info['date'] > $eol) {
                    foreach (array_keys($info['advisories']) as $id) {
                        $ids[(string) $id] = $info['date'];
                    }
                }
            }
        }

        arsort($ids);

        return ['since' => $eol, 'ids' => array_keys($ids)];
    }

    /**
     * @template T
     *
     * @param  array<string, T>  $releases  Keyed by version.
     * @return array<string, T>
     */
    private function newestFirst(array $releases): array
    {
        uksort($releases, fn ($a, $b): int => version_compare((string) $b, (string) $a));

        return $releases;
    }
}
