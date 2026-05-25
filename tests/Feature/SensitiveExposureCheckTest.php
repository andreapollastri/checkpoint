<?php

use Checkpoint\Checks\CheckResult;
use Checkpoint\Checks\SensitiveExposureCheck;

it('passes on clean application code', function () {
    $base = tempProject([
        'app/Providers/AppServiceProvider.php' => "<?php\n\nreturn true;\n",
    ]);

    expect((new SensitiveExposureCheck($base))->run()->status)->toBe(CheckResult::PASS);
});

it('warns when display_errors is enabled', function () {
    $base = tempProject([
        'public/index.php' => "<?php\n\nini_set('display_errors', 1);\n",
    ]);

    expect((new SensitiveExposureCheck($base))->run()->status)->toBe(CheckResult::WARN);
});
