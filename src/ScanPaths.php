<?php

namespace Checkpoint;

use Symfony\Component\Finder\Finder;

class ScanPaths
{
    /** @var string[] */
    public const DEFAULT = [
        'vendor',
        'node_modules',
        'storage',
        'bootstrap/cache',
        '.git',
    ];

    /** @var string[] */
    public const WITH_TESTS = [
        ...self::DEFAULT,
        'tests',
    ];

    /**
     * @param  string[]  $base
     * @return string[]
     */
    public static function merge(array $base): array
    {
        $configured = array_map(
            static fn (string $path): string => trim($path, '/'),
            (array) \config('checkpoint.exclude_paths', []),
        );

        return array_values(array_unique(array_merge($base, $configured)));
    }

    /**
     * @param  string[]  $base
     */
    public static function configure(Finder $finder, array $base = self::DEFAULT): Finder
    {
        return $finder
            ->ignoreUnreadableDirs()
            ->notPath(self::merge($base));
    }
}
