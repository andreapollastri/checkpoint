<?php

use Checkpoint\Checks\CheckResult;
use Checkpoint\Checks\CorsConfigCheck;

it('passes with explicit allowed origins', function () {
    $base = tempProject([
        'config/cors.php' => "<?php\n\nreturn [\n    'allowed_origins' => ['https://example.com'],\n    'supports_credentials' => true,\n];\n",
    ]);

    expect((new CorsConfigCheck($base))->run()->status)->toBe(CheckResult::PASS);
});

it('fails on wildcard origins combined with credentials', function () {
    $base = tempProject([
        'config/cors.php' => "<?php\n\nreturn [\n    'allowed_origins' => ['*'],\n    'supports_credentials' => true,\n];\n",
    ]);

    expect((new CorsConfigCheck($base))->run()->status)->toBe(CheckResult::FAIL);
});

it('warns on wildcard origins without credentials', function () {
    $base = tempProject([
        'config/cors.php' => "<?php\n\nreturn [\n    'allowed_origins' => ['*'],\n    'supports_credentials' => false,\n];\n",
    ]);

    expect((new CorsConfigCheck($base))->run()->status)->toBe(CheckResult::WARN);
});
