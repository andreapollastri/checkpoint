<?php

namespace Checkpoint\Checks;

use Symfony\Component\Process\ExecutableFinder;

class SupplyChainToolingCheck extends AbstractCheck
{
    private const KNOWN_TOOLS = [
        'safe-chain' => 'Safe-Chain (Aikido) — intercepts known malicious npm packages at install time.',
        'socket' => 'Socket CLI — supply-chain risk scanning for npm.',
    ];

    public function __construct(private readonly string $basePath) {}

    public function name(): string
    {
        return 'Supply Chain Tooling';
    }

    public function run(): CheckResult
    {
        if (! file_exists($this->basePath.'/package.json')) {
            return CheckResult::pass('No package.json found — npm supply-chain tooling not applicable.');
        }

        $finder = new ExecutableFinder();
        $found = [];

        foreach (self::KNOWN_TOOLS as $binary => $description) {
            if ($finder->find($binary) !== null) {
                $found[] = "{$binary} — {$description}";
            }
        }

        if (! empty($found)) {
            return CheckResult::pass('Supply-chain tooling detected on PATH.', $found);
        }

        return CheckResult::warn(
            'No npm supply-chain protection tool detected on PATH.',
            [
                'Install Safe-Chain (free, by Aikido) to intercept known-malicious npm packages before they execute:',
                '  npm install -g @aikidosec/safe-chain',
                '  safe-chain setup',
                'Alternative: Socket CLI (npm install -g socket).',
            ]
        );
    }
}
