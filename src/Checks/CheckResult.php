<?php

namespace Checkpoint\Checks;

class CheckResult
{
    public const PASS = 'pass';
    public const WARN = 'warn';
    public const FAIL = 'fail';

    /**
     * @param  list<string>  $details
     * @param  array<string, string>  $hashes  Optional map of detail message => suppression hash.
     */
    public function __construct(
        public readonly string $status,
        public readonly string $message,
        public readonly array $details = [],
        public readonly array $hashes = [],
    ) {}

    /**
     * @param  list<string>  $details
     * @param  array<string, string>  $hashes
     */
    public static function pass(string $message, array $details = [], array $hashes = []): self
    {
        return new self(self::PASS, $message, $details, $hashes);
    }

    /**
     * @param  list<string>  $details
     * @param  array<string, string>  $hashes
     */
    public static function warn(string $message, array $details = [], array $hashes = []): self
    {
        return new self(self::WARN, $message, $details, $hashes);
    }

    /**
     * @param  list<string>  $details
     * @param  array<string, string>  $hashes
     */
    public static function fail(string $message, array $details = [], array $hashes = []): self
    {
        return new self(self::FAIL, $message, $details, $hashes);
    }

    /**
     * Compute a stable 12-char hash for a finding so users can suppress it
     * via config/checkpoint.php → 'suppressed'. Line numbers are stripped
     * from the detail before hashing so refactors that only shift lines
     * do not invalidate the suppression.
     */
    public static function hashFinding(string $checkName, string $detail): string
    {
        $normalized = preg_replace('/:\d+(?=\s*[—-])/', '', $detail);

        return substr(sha1($checkName.'|'.$normalized), 0, 12);
    }

    /**
     * Hash used to suppress this detail. Prefers a check-supplied override
     * when one was stored for the exact detail message.
     */
    public function hashFor(string $checkName, string $detail): string
    {
        return $this->hashes[$detail] ?? self::hashFinding($checkName, $detail);
    }
}
