<?php

use Checkpoint\Checks\CheckResult;
use Checkpoint\Checks\InsecureDeserializationCheck;

it('passes when deserialization restricts allowed classes', function () {
    $base = tempProject([
        'app/Cache/Store.php' => "<?php\n\n\$data = unserialize(\$payload, ['allowed_classes' => false]);\n",
    ]);

    expect((new InsecureDeserializationCheck($base))->run()->status)->toBe(CheckResult::PASS);
});

it('fails on unserialize of dynamic input', function () {
    $base = tempProject([
        'app/Cache/Store.php' => "<?php\n\n\$data = unserialize(\$payload);\n",
    ]);

    expect((new InsecureDeserializationCheck($base))->run()->status)->toBe(CheckResult::FAIL);
});
