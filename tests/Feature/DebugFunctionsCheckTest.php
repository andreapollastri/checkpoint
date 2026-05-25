<?php

use Checkpoint\Checks\CheckResult;
use Checkpoint\Checks\DebugFunctionsCheck;

it('passes when no debug calls are present', function () {
    $base = tempProject([
        'app/Http/Controllers/UserController.php' => "<?php\n\nreturn \$user;\n",
    ]);

    expect((new DebugFunctionsCheck($base))->run()->status)->toBe(CheckResult::PASS);
});

it('warns on a leftover dd call', function () {
    $base = tempProject([
        'app/Http/Controllers/UserController.php' => "<?php\n\ndd(\$user);\n",
    ]);

    expect((new DebugFunctionsCheck($base))->run()->status)->toBe(CheckResult::WARN);
});
