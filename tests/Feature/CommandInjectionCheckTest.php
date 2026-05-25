<?php

use Checkpoint\Checks\CheckResult;
use Checkpoint\Checks\CommandInjectionCheck;

it('passes on static command strings', function () {
    $base = tempProject([
        'app/Jobs/Backup.php' => "<?php\n\nexec('ls -la');\n",
    ]);

    expect((new CommandInjectionCheck($base))->run()->status)->toBe(CheckResult::PASS);
});

it('fails when a variable is passed to a shell function', function () {
    $base = tempProject([
        'app/Jobs/Backup.php' => "<?php\n\nexec(\$userCommand);\n",
    ]);

    expect((new CommandInjectionCheck($base))->run()->status)->toBe(CheckResult::FAIL);
});
