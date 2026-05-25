<?php

use Checkpoint\Checks\CheckResult;
use Checkpoint\Checks\TlsVerificationCheck;

it('passes when TLS verification is left on', function () {
    $base = tempProject([
        'app/Services/ApiClient.php' => "<?php\n\n\$response = Http::get('https://api.example.com');\n",
    ]);

    expect((new TlsVerificationCheck($base))->run()->status)->toBe(CheckResult::PASS);
});

it('fails when TLS verification is disabled', function () {
    $base = tempProject([
        'app/Services/ApiClient.php' => "<?php\n\n\$response = Http::withoutVerifying()->get('https://api.example.com');\n",
    ]);

    expect((new TlsVerificationCheck($base))->run()->status)->toBe(CheckResult::FAIL);
});
