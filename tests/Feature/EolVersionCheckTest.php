<?php

use Checkpoint\Checks\CheckResult;
use Checkpoint\Checks\EolVersionCheck;

it('passes on a supported stack', function () {
    // No composer.lock means no Laravel finding; on PHP 8.3+ there is no PHP finding either.
    $base = tempProject();

    $result = (new EolVersionCheck($base))->run();

    expect($result->status)->toBe(CheckResult::PASS);
})->skip(PHP_VERSION_ID < 80300, 'PHP 8.2 emits a near-EOL warning by design.');

it('fails when composer.lock pins an end-of-life Laravel', function () {
    $base = tempProject([
        'composer.lock' => json_encode([
            'packages' => [
                ['name' => 'laravel/framework', 'version' => 'v10.48.0'],
            ],
        ]),
    ]);

    $result = (new EolVersionCheck($base))->run();

    expect($result->status)->toBe(CheckResult::FAIL);
});
