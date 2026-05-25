<?php

use Checkpoint\Checks\CheckResult;
use Checkpoint\Checks\OpenRedirectCheck;

it('passes on a static redirect', function () {
    $base = tempProject([
        'app/Http/Controllers/HomeController.php' => "<?php\n\nreturn redirect('/home');\n",
    ]);

    expect((new OpenRedirectCheck($base))->run()->status)->toBe(CheckResult::PASS);
});

it('warns on a redirect built from request input', function () {
    $base = tempProject([
        'app/Http/Controllers/HomeController.php' => "<?php\n\nreturn redirect(\$request->url);\n",
    ]);

    expect((new OpenRedirectCheck($base))->run()->status)->toBe(CheckResult::WARN);
});
