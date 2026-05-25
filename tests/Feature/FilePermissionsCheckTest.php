<?php

use Checkpoint\Checks\CheckResult;
use Checkpoint\Checks\FilePermissionsCheck;

it('passes when .env is not world-readable', function () {
    $base = tempProject(['.env' => "APP_KEY=base64:placeholder\n"]);
    chmod($base.'/.env', 0600);

    expect((new FilePermissionsCheck($base))->run()->status)->toBe(CheckResult::PASS);
});

it('warns when .env is world-readable', function () {
    $base = tempProject(['.env' => "APP_KEY=base64:placeholder\n"]);
    chmod($base.'/.env', 0644);

    expect((new FilePermissionsCheck($base))->run()->status)->toBe(CheckResult::WARN);
});
