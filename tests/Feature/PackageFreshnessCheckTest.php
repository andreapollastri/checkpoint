<?php

use Checkpoint\Checks\CheckResult;
use Checkpoint\Checks\PackageFreshnessCheck;

it('passes when every package is older than the threshold', function () {
    $base = tempProject([
        'composer.lock' => json_encode([
            'packages' => [
                ['name' => 'acme/widget', 'version' => 'v1.0.0', 'time' => '2020-01-01T00:00:00+00:00'],
            ],
        ]),
    ]);

    expect((new PackageFreshnessCheck($base))->run()->status)->toBe(CheckResult::PASS);
});

it('fails when a package was released inside the freshness window', function () {
    $base = tempProject([
        'composer.lock' => json_encode([
            'packages' => [
                ['name' => 'acme/widget', 'version' => 'v1.0.0', 'time' => date('c')],
            ],
        ]),
    ]);

    expect((new PackageFreshnessCheck($base))->run()->status)->toBe(CheckResult::FAIL);
});

it('passes when a fresh package is whitelisted', function () {
    $base = tempProject([
        'composer.lock' => json_encode([
            'packages' => [
                ['name' => 'acme/widget', 'version' => 'v1.0.0', 'time' => date('c')],
            ],
        ]),
    ]);

    expect((new PackageFreshnessCheck($base, 3, ['acme/widget']))->run()->status)->toBe(CheckResult::PASS);
});
