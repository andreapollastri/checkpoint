<?php

use Checkpoint\Checks\CheckResult;
use Checkpoint\Checks\NpmAuditCheck;

it('warns when package.json is missing', function () {
    $base = tempProject();

    expect((new NpmAuditCheck($base))->run()->status)->toBe(CheckResult::WARN);
});

it('warns when no lock file is present', function () {
    $base = tempProject([
        'package.json' => "{\n    \"name\": \"app\"\n}\n",
    ]);

    expect((new NpmAuditCheck($base))->run()->status)->toBe(CheckResult::WARN);
});
