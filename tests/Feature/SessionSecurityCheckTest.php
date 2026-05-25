<?php

use Checkpoint\Checks\CheckResult;
use Checkpoint\Checks\SessionSecurityCheck;

it('passes on a hardened session config', function () {
    $base = tempProject([
        'config/session.php' => "<?php\n\nreturn [\n    'http_only' => true,\n    'same_site' => 'lax',\n    'secure' => true,\n    'encrypt' => true,\n];\n",
    ]);

    expect((new SessionSecurityCheck($base))->run()->status)->toBe(CheckResult::PASS);
});

it('warns when http_only is disabled', function () {
    $base = tempProject([
        'config/session.php' => "<?php\n\nreturn [\n    'http_only' => false,\n];\n",
    ]);

    expect((new SessionSecurityCheck($base))->run()->status)->toBe(CheckResult::WARN);
});
