<?php

use Checkpoint\Checks\CheckResult;
use Checkpoint\Checks\InsecureRngCheck;

it('passes when tokens use a CSPRNG', function () {
    $base = tempProject([
        'app/Services/TokenFactory.php' => "<?php\n\n\$token = bin2hex(random_bytes(16));\n",
    ]);

    expect((new InsecureRngCheck($base))->run()->status)->toBe(CheckResult::PASS);
});

it('fails when a token is built with mt_rand', function () {
    $base = tempProject([
        'app/Services/TokenFactory.php' => "<?php\n\n\$token = mt_rand();\n",
    ]);

    expect((new InsecureRngCheck($base))->run()->status)->toBe(CheckResult::FAIL);
});
