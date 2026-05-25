<?php

use Checkpoint\Checks\CheckResult;
use Checkpoint\Checks\XssCheck;

it('passes when blade output is escaped', function () {
    $base = tempProject([
        'resources/views/profile.blade.php' => "<div>{{ \$name }}</div>\n",
    ]);

    expect((new XssCheck($base))->run()->status)->toBe(CheckResult::PASS);
});

it('warns on unescaped blade output', function () {
    $base = tempProject([
        'resources/views/profile.blade.php' => "<div>{!! \$userInput !!}</div>\n",
    ]);

    expect((new XssCheck($base))->run()->status)->toBe(CheckResult::WARN);
});
