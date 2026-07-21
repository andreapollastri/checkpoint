<?php

namespace Checkpoint\Tests\Unit\Checks;

use Checkpoint\Checks\CheckResult;
use Checkpoint\Checks\SqlInjectionCheck;
use Checkpoint\Tests\TestCase;

class SqlInjectionCheckTest extends TestCase
{
    public function test_passes_on_a_clean_codebase(): void
    {
        $workspace = $this->makeWorkspace();
        $this->writeFile(
            $workspace,
            'app/Repositories/UserRepository.php',
            "<?php\nDB::select('select * from users where id = ?', [\$id]);\n",
        );

        $result = (new SqlInjectionCheck($workspace))->run();

        $this->assertSame(CheckResult::PASS, $result->status);
    }

    public function test_detects_interpolated_variable_in_db_select(): void
    {
        $workspace = $this->makeWorkspace();
        $this->writeFile(
            $workspace,
            'app/Repositories/UserRepository.php',
            "<?php\nDB::select(\"select * from users where email = '\$email'\");\n",
        );

        $result = (new SqlInjectionCheck($workspace))->run();

        $this->assertSame(CheckResult::FAIL, $result->status);
        $this->assertStringContainsString('UserRepository.php', $result->details[0]);
    }

    public function test_detects_where_raw_with_interpolation(): void
    {
        $workspace = $this->makeWorkspace();
        $this->writeFile(
            $workspace,
            'app/Models/Order.php',
            "<?php\n\$query->whereRaw(\"status = '\$status'\");\n",
        );

        $result = (new SqlInjectionCheck($workspace))->run();

        $this->assertSame(CheckResult::FAIL, $result->status);
    }

    public function test_skips_vendor_directory(): void
    {
        $workspace = $this->makeWorkspace();
        $this->writeFile(
            $workspace,
            'vendor/acme/lib/Query.php',
            "<?php\nDB::select(\"select * from users where email = '\$email'\");\n",
        );

        $result = (new SqlInjectionCheck($workspace))->run();

        $this->assertSame(CheckResult::PASS, $result->status);
    }

    public function test_name_is_stable(): void
    {
        $this->assertSame('SQL Injection Risks', (new SqlInjectionCheck($this->makeWorkspace()))->name());
    }
}
