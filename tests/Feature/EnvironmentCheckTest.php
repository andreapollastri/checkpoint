<?php

use Checkpoint\Checks\CheckResult;
use Checkpoint\Checks\EnvironmentCheck;

function productionConfig(): void
{
    config([
        'app.debug' => false,
        'app.env' => 'production',
        'app.key' => 'base64:'.base64_encode(random_bytes(32)),
        'app.url' => 'https://example.com',
        'session.secure' => true,
        'session.driver' => 'database',
    ]);
}

it('passes with production-safe configuration', function () {
    productionConfig();
    $base = tempProject(['.env' => "APP_ENV=production\n"]);

    expect((new EnvironmentCheck($base))->run()->status)->toBe(CheckResult::PASS);
});

it('warns when APP_DEBUG is enabled', function () {
    productionConfig();
    config(['app.debug' => true]);
    $base = tempProject(['.env' => "APP_ENV=production\n"]);

    expect((new EnvironmentCheck($base))->run()->status)->toBe(CheckResult::WARN);
});
