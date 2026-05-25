<?php

use Checkpoint\Checks\CheckResult;
use Checkpoint\Checks\GitIgnoreCheck;

it('fails when .gitignore is missing', function () {
    $base = tempProject();

    expect((new GitIgnoreCheck($base))->run()->status)->toBe(CheckResult::FAIL);
});

it('passes when sensitive patterns are ignored', function () {
    $base = tempProject([
        '.gitignore' => ".env\n*.key\n*.pem\nstorage/logs\n.env.backup\n.env.production\n",
    ]);

    expect((new GitIgnoreCheck($base))->run()->status)->toBe(CheckResult::PASS);
});

it('warns when some patterns are missing', function () {
    $base = tempProject([
        '.gitignore' => ".env\n",
    ]);

    expect((new GitIgnoreCheck($base))->run()->status)->toBe(CheckResult::WARN);
});
