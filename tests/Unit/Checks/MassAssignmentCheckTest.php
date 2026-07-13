<?php

namespace Checkpoint\Tests\Unit\Checks;

use Checkpoint\Checks\CheckResult;
use Checkpoint\Checks\MassAssignmentCheck;
use Checkpoint\Tests\TestCase;

class MassAssignmentCheckTest extends TestCase
{
    public function test_passes_for_abstract_models_without_local_fillable_or_guarded(): void
    {
        $workspace = $this->makeWorkspace();
        $this->writeFile(
            $workspace,
            'app/Models/BaseModel.php',
            "<?php\n\nnamespace App\\Models;\n\nuse Illuminate\\Database\\Eloquent\\Model;\n\nabstract class BaseModel extends Model\n{\n}\n",
        );

        $result = (new MassAssignmentCheck($workspace))->run();

        $this->assertSame(CheckResult::PASS, $result->status);
    }

    public function test_passes_for_models_relying_on_default_guarded_behavior(): void
    {
        $workspace = $this->makeWorkspace();
        $this->writeFile(
            $workspace,
            'app/Models/User.php',
            "<?php\n\nnamespace App\\Models;\n\nuse Illuminate\\Database\\Eloquent\\Model;\n\nclass User extends Model\n{\n}\n",
        );

        $result = (new MassAssignmentCheck($workspace))->run();

        $this->assertSame(CheckResult::PASS, $result->status);
    }

    public function test_warns_when_guarded_is_explicitly_empty(): void
    {
        $workspace = $this->makeWorkspace();
        $this->writeFile(
            $workspace,
            'app/Models/User.php',
            "<?php\n\nnamespace App\\Models;\n\nuse Illuminate\\Database\\Eloquent\\Model;\n\nclass User extends Model\n{\n    protected \$guarded = [];\n}\n",
        );

        $result = (new MassAssignmentCheck($workspace))->run();

        $this->assertSame(CheckResult::WARN, $result->status);
        $this->assertStringContainsString('1 potential mass assignment issue', $result->message);
        $this->assertStringContainsString('$guarded = []', $result->details[0]);
    }
}
