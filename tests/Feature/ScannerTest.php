<?php

use Checkpoint\Checks\CheckResult;
use Checkpoint\Checks\EolVersionCheck;
use Checkpoint\Scanner;

it('runs registered checks and keys results by check name', function () {
    $scanner = (new Scanner)->add(new EolVersionCheck(tempProject()));

    $results = $scanner->run();

    expect($results)->toHaveKey('EOL Versions')
        ->and($results['EOL Versions'])->toBeInstanceOf(CheckResult::class);
});
