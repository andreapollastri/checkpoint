<?php

use Checkpoint\Checks\CheckResult;
use Checkpoint\Checks\HardcodedSecretsCheck;

it('passes when secrets are read from the environment', function () {
    $base = tempProject([
        'app/Services/PaymentService.php' => "<?php\n\n\$key = env('STRIPE_KEY');\n",
    ]);

    $result = (new HardcodedSecretsCheck($base))->run();

    expect($result->status)->toBe(CheckResult::PASS);
});

it('fails when a secret is hardcoded in source', function () {
    $base = tempProject([
        'app/Services/PaymentService.php' => "<?php\n\n\$config = ['stripe_key' => 'fake-test-secret'];\n",
    ]);

    $result = (new HardcodedSecretsCheck($base))->run();

    expect($result->status)->toBe(CheckResult::FAIL)
        ->and($result->details)->not->toBeEmpty();
});
