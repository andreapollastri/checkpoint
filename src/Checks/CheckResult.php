<?php

namespace Checkpoint\Checks;

class CheckResult
{
    public const PASS = 'pass';
    public const WARN = 'warn';
    public const FAIL = 'fail';

    public function __construct(
        public readonly string $status,
        public readonly string $message,
        public readonly array $details = [],
    ) {}

    public static function pass(string $message, array $details = []): self
    {
        return new self(self::PASS, $message, $details);
    }

    public static function warn(string $message, array $details = []): self
    {
        return new self(self::WARN, $message, $details);
    }

    public static function fail(string $message, array $details = []): self
    {
        return new self(self::FAIL, $message, $details);
    }
}
