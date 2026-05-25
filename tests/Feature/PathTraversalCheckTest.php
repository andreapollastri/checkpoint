<?php

use Checkpoint\Checks\CheckResult;
use Checkpoint\Checks\PathTraversalCheck;

it('passes on a fixed storage path', function () {
    $base = tempProject([
        'app/Http/Controllers/FileController.php' => "<?php\n\nStorage::get('avatars/default.png');\n",
    ]);

    expect((new PathTraversalCheck($base))->run()->status)->toBe(CheckResult::PASS);
});

it('fails when storage path comes from request input', function () {
    $base = tempProject([
        'app/Http/Controllers/FileController.php' => "<?php\n\nStorage::get(\$request->path);\n",
    ]);

    expect((new PathTraversalCheck($base))->run()->status)->toBe(CheckResult::FAIL);
});
