<?php

use Checkpoint\Checks\CheckResult;
use Checkpoint\Checks\SupplyChainToolingCheck;
use Symfony\Component\Process\ExecutableFinder;

it('passes when there is no package.json', function () {
    $base = tempProject();

    expect((new SupplyChainToolingCheck($base))->run()->status)->toBe(CheckResult::PASS);
});

it('warns when a node project has no supply-chain guard on PATH', function () {
    $base = tempProject([
        'package.json' => "{\n    \"name\": \"app\"\n}\n",
    ]);

    expect((new SupplyChainToolingCheck($base))->run()->status)->toBe(CheckResult::WARN);
})->skip(
    (new ExecutableFinder)->find('safe-chain') !== null
        || (new ExecutableFinder)->find('socket') !== null,
    'A supply-chain tool is installed on PATH, so this environment would pass.'
);
