<?php

use Checkpoint\Checks\CheckResult;
use Checkpoint\Checks\SsrfCheck;

it('passes when the request URL is a fixed endpoint', function () {
    $base = tempProject([
        'app/Services/Webhook.php' => "<?php\n\nHttp::get('https://api.example.com/data');\n",
    ]);

    expect((new SsrfCheck($base))->run()->status)->toBe(CheckResult::PASS);
});

it('fails when an HTTP client is called with user input', function () {
    $base = tempProject([
        'app/Services/Webhook.php' => "<?php\n\nHttp::get(\$request->url);\n",
    ]);

    expect((new SsrfCheck($base))->run()->status)->toBe(CheckResult::FAIL);
});
