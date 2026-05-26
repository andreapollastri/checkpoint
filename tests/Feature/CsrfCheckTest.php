<?php

use Checkpoint\Checks\CheckResult;
use Checkpoint\Checks\CsrfCheck;

it('passes when a mutable form includes the csrf directive', function () {
    $base = tempProject([
        'resources/views/contact.blade.php' => "<form method=\"POST\">@csrf<input name=\"x\"></form>\n",
    ]);

    expect((new CsrfCheck($base))->run()->status)->toBe(CheckResult::PASS);
});

it('fails when a post form is missing the csrf directive', function () {
    $base = tempProject([
        'resources/views/contact.blade.php' => "<form method=\"POST\"><input name=\"x\"></form>\n",
    ]);

    expect((new CsrfCheck($base))->run()->status)->toBe(CheckResult::FAIL);
});

it('ignores livewire forms that submit via wire:submit', function () {
    $base = tempProject([
        'resources/views/contact.blade.php' => "<form method=\"POST\" wire:submit=\"save\"><input name=\"x\"></form>\n",
    ]);

    expect((new CsrfCheck($base))->run()->status)->toBe(CheckResult::PASS);
});
