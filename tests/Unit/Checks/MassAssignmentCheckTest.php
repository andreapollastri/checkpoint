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
            <<<'PHP'
<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Model;

abstract class BaseModel extends Model
{
}
PHP,
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
            <<<'PHP'
<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Model;

class User extends Model
{
}
PHP,
        );

        $result = (new MassAssignmentCheck($workspace))->run();

        $this->assertSame(CheckResult::PASS, $result->status);
    }

    public function test_warns_when_abstract_model_disables_guarding(): void
    {
        $workspace = $this->makeWorkspace();
        $this->writeFile(
            $workspace,
            'app/Models/BaseModel.php',
            <<<'PHP'
<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Model;

abstract class BaseModel extends Model
{
    protected $guarded = [];
}
PHP,
        );

        $result = (new MassAssignmentCheck($workspace))->run();

        $this->assertSame(CheckResult::WARN, $result->status);
        $this->assertStringContainsString('$guarded = [] in abstract model', $result->details[0]);
        $this->assertStringContainsString('child models', $result->details[0]);
    }

    public function test_passes_when_guarded_blocks_all_attributes(): void
    {
        $workspace = $this->makeWorkspace();
        $this->writeFile(
            $workspace,
            'app/Models/User.php',
            <<<'PHP'
<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Model;

class User extends Model
{
    protected $guarded = ['*'];
}
PHP,
        );

        $result = (new MassAssignmentCheck($workspace))->run();

        $this->assertSame(CheckResult::PASS, $result->status);
    }

    public function test_passes_for_model_inheriting_guarding_from_abstract_base(): void
    {
        $workspace = $this->makeWorkspace();
        $this->writeFile(
            $workspace,
            'app/Models/BaseModel.php',
            <<<'PHP'
<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Model;

abstract class BaseModel extends Model
{
    protected $guarded = ['*'];
}
PHP,
        );
        $this->writeFile(
            $workspace,
            'app/Models/User.php',
            <<<'PHP'
<?php

namespace App\Models;

class User extends BaseModel
{
}
PHP,
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
            <<<'PHP'
<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Model;

class User extends Model
{
    protected $guarded = [];
}
PHP,
        );

        $result = (new MassAssignmentCheck($workspace))->run();

        $this->assertSame(CheckResult::WARN, $result->status);
        $this->assertStringContainsString('1 potential mass assignment issue', $result->message);
        $this->assertStringContainsString('$guarded = []', $result->details[0]);
    }

    public function test_warns_on_model_unguard(): void
    {
        $workspace = $this->makeWorkspace();
        $this->writeFile(
            $workspace,
            'app/Models/User.php',
            <<<'PHP'
<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Model;

class User extends Model
{
    protected static function booted(): void
    {
        Model::unguard();
    }
}
PHP,
        );

        $result = (new MassAssignmentCheck($workspace))->run();

        $this->assertSame(CheckResult::WARN, $result->status);
        $this->assertStringContainsString('Model::unguard()', implode("\n", $result->details));
    }
}
