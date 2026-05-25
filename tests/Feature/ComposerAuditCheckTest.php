<?php

use Checkpoint\Checks\CheckResult;
use Checkpoint\Checks\ComposerAuditCheck;

it('warns when composer.lock is missing', function () {
    $base = tempProject();

    expect((new ComposerAuditCheck($base))->run()->status)->toBe(CheckResult::WARN);
});
