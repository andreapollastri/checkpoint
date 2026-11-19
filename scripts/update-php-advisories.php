#!/usr/bin/env php
<?php

/**
 * Regenerates resources/php-advisories.php — the bundled database used by the
 * "PHP CVE Audit" check — from php.net.
 *
 *   php scripts/update-php-advisories.php
 *
 * Sources:
 *   - https://www.php.net/ChangeLog-8.php          CVE / GHSA ids fixed per release
 *   - https://www.php.net/releases/index.php?json  release dates + "security" tags
 *
 * Run it after every PHP security release and commit the result. Between
 * package releases the check covers the gap by asking php.net directly.
 */

const OLDEST_BRANCH = '8.1'; // the package floor (composer.json → php ^8.1)
const CHANGELOGS = ['https://www.php.net/ChangeLog-8.php'];
const RELEASE_FEED = 'https://www.php.net/releases/index.php?json&max=500&version=';
const TARGET = __DIR__.'/../resources/php-advisories.php';

function fetch(string $url): string
{
    $context = stream_context_create(['http' => [
        'timeout' => 60,
        'user_agent' => 'andreapollastri/checkpoint advisory updater',
    ]]);

    $body = @file_get_contents($url, false, $context);

    if ($body === false || $body === '') {
        fwrite(STDERR, "Could not fetch {$url}\n");
        exit(1);
    }

    return $body;
}

/**
 * @return array{id: string, title: string}|null  null when the entry carries no advisory id.
 */
function parseAdvisory(string $component, string $text): ?array
{
    $text = trim((string) preg_replace('/\s+/', ' ', html_entity_decode(strip_tags($text), ENT_QUOTES | ENT_HTML5)));

    // The entry's own CVE is the trailing "(CVE-…)"; CVEs named inside the
    // description ("Bypass of CVE-2012-1823") are older, related issues.
    $cve = null;
    if (preg_match('/\s*\((CVE-\d{4}-\d+)\)\.?$/', $text, $m)) {
        $cve = $m[1];
        $text = trim(substr($text, 0, -strlen($m[0])));
    } elseif (preg_match('/^Fix(?:ed)?(?: bug)? (CVE-\d{4}-\d+)\b/', $text, $m)) {
        $cve = $m[1];
    }

    preg_match_all('/GHSA-[0-9a-z]{4}-[0-9a-z]{4}-[0-9a-z]{4}/', $text, $ghsa);

    if ($cve === null && $ghsa[0] === []) {
        return null;
    }

    // "Fixed bug GHSA-xxxx and GH-123 (Title)." → "Title"
    $reference = '(?:GHSA-[0-9a-z-]+|GH-\d+|#\d+|CVE-\d{4}-\d+)';
    $title = (string) preg_replace('/^Fix(?:ed)?(?: bug)? '.$reference.'(?:\s*(?:,|and)\s*'.$reference.')*\s*/', '', $text);
    $title = rtrim(ltrim($title, ': '), '.');

    if (str_starts_with($title, '(') && str_ends_with($title, ')')) {
        $title = substr($title, 1, -1);
    }

    return [
        'id' => $cve ?? implode(' / ', array_unique($ghsa[0])),
        'title' => $component.': '.rtrim(trim($title), '.'),
    ];
}

// ---- 1. Advisory ids per release, from the changelog -----------------------

$releases = [];

foreach (CHANGELOGS as $url) {
    preg_match_all('~<section class="version" id="(\d+\.\d+)\.(\d+)">(.*?)</section>~s', fetch($url), $sections, PREG_SET_ORDER);

    foreach ($sections as [, $branch, $patch, $html]) {
        // x.y.0 only fixes issues found in its own pre-releases.
        if (version_compare($branch, OLDEST_BRANCH, '<') || $patch === '0') {
            continue;
        }

        $advisories = [];
        preg_match_all('~<li>([^<:]+):\s*<ul>(.*?)</ul>\s*</li>~s', $html, $components, PREG_SET_ORDER);

        foreach ($components as [, $component, $items]) {
            preg_match_all('~<li>(.*?)</li>~s', $items, $entries);

            foreach ($entries[1] as $entry) {
                $advisory = parseAdvisory(trim($component), $entry);

                if ($advisory !== null) {
                    $advisories[$advisory['id']] ??= $advisory['title'];
                }
            }
        }

        $date = preg_match("~datetime='(\d{4}-\d{2}-\d{2})'~", $html, $m) ? $m[1] : '';
        $releases[$branch]["{$branch}.{$patch}"] = ['date' => $date, 'advisories' => $advisories];
    }
}

// ---- 2. Release dates + security tags, from the release feed ---------------

foreach (array_keys($releases) as $branch) {
    $feed = json_decode(fetch(RELEASE_FEED.$branch), true);

    if (! is_array($feed) || isset($feed['error'])) {
        fwrite(STDERR, "Unexpected release feed for PHP {$branch}\n");
        exit(1);
    }

    foreach ($feed as $version => $release) {
        $version = (string) $version;
        $security = in_array('security', (array) ($release['tags'] ?? []), true);
        $timestamp = strtotime((string) ($release['date'] ?? ''));

        if ($timestamp !== false && isset($releases[$branch][$version])) {
            $releases[$branch][$version]['date'] = gmdate('Y-m-d', $timestamp);
        }

        if (isset($releases[$branch][$version])) {
            $releases[$branch][$version]['security'] = $security;
        }
    }
}

// ---- 3. Keep only releases that fix something, sorted ----------------------

foreach ($releases as $branch => $versions) {
    // A release tagged "security" upstream is kept even when its changelog
    // names no CVE / GHSA — the check reports it as a generic security release.
    $versions = array_filter(
        $versions,
        fn (array $release): bool => $release['advisories'] !== [] || ($release['security'] ?? false),
    );
    uksort($versions, 'version_compare');
    $releases[$branch] = $versions;
}

$releases = array_filter($releases);
uksort($releases, 'version_compare');

// ---- 4. Write the database -------------------------------------------------

$export = static fn (string $value): string => "'".addcslashes($value, "'\\")."'";

$php = "<?php\n\n";
$php .= "/*\n";
$php .= " * Security releases of PHP and the advisories (CVE / GHSA) each one fixes.\n";
$php .= " *\n";
$php .= " * GENERATED FILE — do not edit by hand. Regenerate with:\n";
$php .= " *\n";
$php .= " *     php scripts/update-php-advisories.php\n";
$php .= " *\n";
$php .= " * Sources: https://www.php.net/ChangeLog-8.php, https://www.php.net/releases/\n";
$php .= " */\n\n";
$php .= "return [\n\n";
$php .= "    'generated' => ".$export(gmdate('Y-m-d')).",\n\n";
$php .= "    // branch => [fixed-in version => [release date, advisory id => summary]]\n";
$php .= "    'releases' => [\n";

$count = 0;

foreach ($releases as $branch => $versions) {
    $php .= "\n        ".$export((string) $branch)." => [\n";

    foreach ($versions as $version => $release) {
        $php .= '            '.$export((string) $version)." => [\n";
        $php .= "                'date' => ".$export($release['date']).",\n";
        $php .= "                'advisories' => [".($release['advisories'] === [] ? '' : "\n");

        foreach ($release['advisories'] as $id => $title) {
            $php .= '                    '.$export((string) $id).' => '.$export($title).",\n";
            $count++;
        }

        $php .= ($release['advisories'] === [] ? '' : '                ')."],\n";
        $php .= "            ],\n";
    }

    $php .= "        ],\n";
}

$php .= "\n    ],\n\n];\n";

if (! is_dir(dirname(TARGET))) {
    mkdir(dirname(TARGET), 0755, true);
}

file_put_contents(TARGET, $php);

printf(
    "Wrote %s — %d advisory fixes across %d releases in %d branches (%s).\n",
    realpath(TARGET),
    $count,
    array_sum(array_map('count', $releases)),
    count($releases),
    implode(', ', array_keys($releases)),
);
