<?php

use Checkpoint\Checks\CheckResult;
use Checkpoint\Checks\SqlInjectionCheck;

it('passes when queries use bindings', function () {
    $base = tempProject([
        'app/Repositories/UserRepository.php' => "<?php\n\nDB::select('SELECT * FROM users WHERE id = ?', [\$id]);\n",
    ]);

    expect((new SqlInjectionCheck($base))->run()->status)->toBe(CheckResult::PASS);
});

it('fails on raw queries with interpolated variables', function () {
    $base = tempProject([
        'app/Repositories/UserRepository.php' => "<?php\n\nDB::select(\"SELECT * FROM users WHERE id = \$id\");\n",
    ]);

    expect((new SqlInjectionCheck($base))->run()->status)->toBe(CheckResult::FAIL);
});
