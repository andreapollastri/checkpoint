<?php

namespace Checkpoint\Checks;

class ComposerConfigCheck extends AbstractCheck
{
    /** `config` keys that hold registry credentials and belong in auth.json instead. */
    private const CREDENTIAL_KEYS = [
        'http-basic',
        'bearer',
        'github-oauth',
        'gitlab-oauth',
        'gitlab-token',
        'bitbucket-oauth',
    ];

    private const UNSTABLE = ['dev', 'alpha', 'beta', 'rc'];

    public function __construct(private readonly string $basePath) {}

    public function name(): string
    {
        return 'Composer Configuration';
    }

    public function run(): CheckResult
    {
        $path = $this->basePath.'/composer.json';

        if (! file_exists($path)) {
            return CheckResult::warn('composer.json not found — skipping Composer configuration check.');
        }

        $manifest = @json_decode((string) file_get_contents($path), true);
        if (! is_array($manifest)) {
            return CheckResult::warn('composer.json is not valid JSON — skipping Composer configuration check.');
        }

        $config = is_array($manifest['config'] ?? null) ? $manifest['config'] : [];
        $critical = [];
        $warnings = [];

        // ---- Transport security ----
        if (($config['secure-http'] ?? true) === false) {
            $critical[] = 'config.secure-http is false — Composer may download packages over plain HTTP, open to tampering in transit.';
        }

        if (($config['disable-tls'] ?? false) === true) {
            $critical[] = 'config.disable-tls is true — TLS is disabled for every Composer download.';
        }

        foreach ((array) ($manifest['repositories'] ?? []) as $repository) {
            $url = is_array($repository) ? ($repository['url'] ?? null) : null;

            if (is_string($url) && stripos($url, 'http://') === 0) {
                $critical[] = "repositories: {$url} uses plain HTTP — packages can be tampered with in transit.";
            }
        }

        // ---- Committed credentials ----
        foreach (self::CREDENTIAL_KEYS as $key) {
            if (! empty($config[$key])) {
                $critical[] = "config.{$key} stores registry credentials in composer.json — move them to auth.json (git-ignored) or the COMPOSER_AUTH env var, and rotate them.";
            }
        }

        // ---- Plugins ----
        if (($config['allow-plugins'] ?? null) === true) {
            $warnings[] = 'config.allow-plugins is true — any Composer plugin, including ones pulled in by future dependencies, can run code during install. List trusted plugins explicitly.';
        }

        // ---- Stability ----
        $stability = strtolower((string) ($manifest['minimum-stability'] ?? 'stable'));
        if (in_array($stability, self::UNSTABLE, true) && ($manifest['prefer-stable'] ?? false) !== true) {
            $warnings[] = "minimum-stability is \"{$stability}\" without prefer-stable — Composer may resolve to unreleased, unreviewed versions.";
        }

        // ---- Audit settings ----
        $audit = is_array($config['audit'] ?? null) ? $config['audit'] : [];

        if (($audit['block-insecure'] ?? true) === false) {
            $warnings[] = 'config.audit.block-insecure is false — `composer update` will install versions with known security advisories.';
        }

        $ignored = $this->ignoredAdvisories($audit['ignore'] ?? []);
        if ($ignored !== []) {
            $list = implode(', ', array_slice($ignored, 0, 5)).(count($ignored) > 5 ? ', …' : '');
            $warnings[] = 'config.audit.ignore silences '.count($ignored)." advisory(ies) — `composer audit` and the Composer CVE Audit check will not report them: {$list}";
        }

        $findings = array_merge($critical, $warnings);

        if (empty($findings)) {
            return CheckResult::pass('Composer configuration enforces secure downloads and stable dependencies.');
        }

        $message = count($findings).' insecure Composer setting(s) in composer.json.';

        return empty($critical)
            ? CheckResult::warn($message, $findings)
            : CheckResult::fail($message, $findings);
    }

    /**
     * `audit.ignore` is either a list of IDs or a map of ID => reason.
     *
     * @return list<string>
     */
    private function ignoredAdvisories(mixed $ignore): array
    {
        if (! is_array($ignore)) {
            return [];
        }

        $ids = array_is_list($ignore) ? $ignore : array_keys($ignore);

        return array_values(array_filter(
            array_map('strval', $ids),
            static fn (string $id): bool => $id !== '',
        ));
    }
}
