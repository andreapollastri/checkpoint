<?php

namespace Checkpoint\Tests\Unit\Checks;

use Checkpoint\Checks\CheckResult;
use Checkpoint\Checks\HardcodedSecretsCheck;
use Checkpoint\Tests\TestCase;
use ReflectionMethod;

class HardcodedSecretsCheckTest extends TestCase
{
    public function test_passes_on_a_clean_codebase(): void
    {
        $workspace = $this->makeWorkspace();
        $this->writeFile($workspace, 'app/Clean.php', "<?php\n\$value = 'just a string';\n");

        $result = (new HardcodedSecretsCheck($workspace))->run();

        $this->assertSame(CheckResult::PASS, $result->status);
    }

    public function test_detects_a_stripe_secret_key(): void
    {
        $workspace = $this->makeWorkspace();
        $this->writeFile(
            $workspace,
            'app/Services/PaymentService.php',
            "<?php\nreturn ['api_key' => 'sk_live_abcdefghijABCDEFGHIJ1234'];\n",
        );

        $result = (new HardcodedSecretsCheck($workspace))->run();

        $this->assertSame(CheckResult::FAIL, $result->status);
        $this->assertStringContainsString('1 potential hardcoded secret', $result->message);
        $this->assertStringContainsString('PaymentService.php', $result->details[0]);
    }

    public function test_detects_an_aws_access_key(): void
    {
        $workspace = $this->makeWorkspace();
        $this->writeFile($workspace, 'app/Config.php', "<?php\n\$key = 'AKIAIOSFODNN7EXAMPLE';\n");

        $result = (new HardcodedSecretsCheck($workspace))->run();

        $this->assertSame(CheckResult::FAIL, $result->status);
    }

    public function test_ignores_values_pulled_from_env(): void
    {
        $workspace = $this->makeWorkspace();
        $this->writeFile(
            $workspace,
            'app/Config.php',
            "<?php\n\$apiKey = env('API_KEY', 'sk_live_abcdefghijABCDEFGHIJ1234');\n",
        );

        $result = (new HardcodedSecretsCheck($workspace))->run();

        $this->assertSame(CheckResult::PASS, $result->status);
    }

    public function test_ignores_language_files(): void
    {
        $workspace = $this->makeWorkspace();
        $this->writeFile(
            $workspace,
            'lang/en/auth.php',
            "<?php\nreturn ['password' => 'The provided password is incorrect.'];\n",
        );

        $result = (new HardcodedSecretsCheck($workspace))->run();

        $this->assertSame(CheckResult::PASS, $result->status);
    }

    public function test_skips_files_under_the_vendor_directory(): void
    {
        $workspace = $this->makeWorkspace();
        $this->writeFile(
            $workspace,
            'vendor/acme/lib/src/Secret.php',
            "<?php\nreturn ['api_key' => 'sk_live_abcdefghijABCDEFGHIJ1234'];\n",
        );

        $result = (new HardcodedSecretsCheck($workspace))->run();

        $this->assertSame(CheckResult::PASS, $result->status);
    }

    public function test_skips_paths_configured_in_exclude_paths(): void
    {
        config()->set('checkpoint.exclude_paths', ['storage/app/mounted-data']);

        $workspace = $this->makeWorkspace();
        $this->writeFile(
            $workspace,
            'storage/app/mounted-data/Secret.php',
            "<?php\nreturn ['api_key' => 'sk_live_abcdefghijABCDEFGHIJ1234'];\n",
        );

        $result = (new HardcodedSecretsCheck($workspace))->run();

        $this->assertSame(CheckResult::PASS, $result->status);
    }

    public function test_name_is_stable(): void
    {
        $this->assertSame('Hardcoded Secrets', (new HardcodedSecretsCheck($this->makeWorkspace()))->name());
    }

    public function test_allows_a_hashed_password_cast(): void
    {
        $workspace = $this->makeWorkspace();
        $this->writeFile(
            $workspace,
            'app/Models/User.php',
            "<?php\nclass User {\n    protected \$casts = ['password' => 'hashed'];\n}\n",
        );

        $result = (new HardcodedSecretsCheck($workspace))->run();

        $this->assertSame(CheckResult::PASS, $result->status);
    }

    public function test_allows_an_encrypted_cast(): void
    {
        $workspace = $this->makeWorkspace();
        $this->writeFile(
            $workspace,
            'app/Models/Integration.php',
            "<?php\nclass Integration {\n    protected \$casts = ['api_key' => 'encrypted'];\n}\n",
        );

        $result = (new HardcodedSecretsCheck($workspace))->run();

        $this->assertSame(CheckResult::PASS, $result->status);
    }

    public function test_allows_an_encrypted_variant_cast(): void
    {
        $workspace = $this->makeWorkspace();
        $this->writeFile(
            $workspace,
            'app/Models/Integration.php',
            "<?php\nclass Integration {\n    protected \$casts = ['token' => 'encrypted:array'];\n}\n",
        );

        $result = (new HardcodedSecretsCheck($workspace))->run();

        $this->assertSame(CheckResult::PASS, $result->status);
    }

    public function test_flags_casts_that_do_not_protect_the_value(): void
    {
        $workspace = $this->makeWorkspace();
        $this->writeFile(
            $workspace,
            'app/Models/Integration.php',
            "<?php\nclass Integration {\n    protected \$casts = ['api_key' => 'array'];\n}\n",
        );

        $result = (new HardcodedSecretsCheck($workspace))->run();

        $this->assertSame(CheckResult::FAIL, $result->status);
    }

    public function test_cast_matcher_accepts_only_hashed_and_encrypted_casts(): void
    {
        $expectations = [
            "'password' => 'hashed'," => true,
            "'api_key' => 'encrypted'," => true,
            "'token' => 'encrypted:collection'," => true,
            "'secrets' => AsEncryptedCollection::class," => true,
            "'secrets' => \\Illuminate\\Database\\Eloquent\\Casts\\AsEncryptedArrayObject::class," => true,
            "'name' => 'string'," => false,
            "'settings' => 'array'," => false,
            "'meta' => AsStringable::class," => false,
            // Quoted string values must not be mistaken for a cast class constant
            "'token' => 'AsEncryptedCollection::class'," => false,
            // The cast name must be the whole quoted value
            "'password' => 'hashed_secret_123'," => false,
        ];

        $matcher = new ReflectionMethod(HardcodedSecretsCheck::class, 'isHashedOrEncryptedCast');
        $check = new HardcodedSecretsCheck($this->makeWorkspace());

        foreach ($expectations as $line => $expected) {
            $this->assertSame(
                $expected,
                $matcher->invoke($check, $line),
                "Unexpected cast match result for line: {$line}",
            );
        }
    }
}
