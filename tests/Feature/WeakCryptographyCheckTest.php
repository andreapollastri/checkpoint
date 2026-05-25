<?php

use Checkpoint\Checks\CheckResult;
use Checkpoint\Checks\WeakCryptographyCheck;

it('passes when using strong hashing', function () {
    $base = tempProject([
        'app/Support/Crypto.php' => "<?php\n\n\$hash = password_hash(\$pw, PASSWORD_BCRYPT);\n",
    ]);

    expect((new WeakCryptographyCheck($base))->run()->status)->toBe(CheckResult::PASS);
});

it('fails on deprecated mcrypt usage', function () {
    $base = tempProject([
        'app/Support/Crypto.php' => "<?php\n\n\$enc = mcrypt_encrypt(\$cipher, \$key, \$data, \$mode);\n",
    ]);

    expect((new WeakCryptographyCheck($base))->run()->status)->toBe(CheckResult::FAIL);
});

it('warns on a weak hash in a security context', function () {
    $base = tempProject([
        'app/Support/Crypto.php' => "<?php\n\n\$signature = md5(\$password . \$salt);\n",
    ]);

    expect((new WeakCryptographyCheck($base))->run()->status)->toBe(CheckResult::WARN);
});
