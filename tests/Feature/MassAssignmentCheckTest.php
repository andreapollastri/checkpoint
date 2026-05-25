<?php

use Checkpoint\Checks\CheckResult;
use Checkpoint\Checks\MassAssignmentCheck;

it('passes when a model defines fillable', function () {
    $base = tempProject([
        'app/Models/Post.php' => "<?php\n\nclass Post extends Model\n{\n    protected \$fillable = ['title'];\n}\n",
    ]);

    expect((new MassAssignmentCheck($base))->run()->status)->toBe(CheckResult::PASS);
});

it('warns when a model sets guarded to an empty array', function () {
    $base = tempProject([
        'app/Models/User.php' => "<?php\n\nclass User extends Model\n{\n    protected \$guarded = [];\n}\n",
    ]);

    expect((new MassAssignmentCheck($base))->run()->status)->toBe(CheckResult::WARN);
});
