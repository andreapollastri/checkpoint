<?php

namespace Checkpoint\Tests\Unit\Checks;

use Checkpoint\Checks\CheckResult;
use Checkpoint\Checks\TlsVerificationCheck;
use Checkpoint\Tests\TestCase;

class TlsVerificationCheckTest extends TestCase
{
    public function test_passes_on_a_clean_codebase(): void
    {
        $workspace = $this->makeWorkspace();
        $this->writeFile(
            $workspace,
            'app/Services/HttpClient.php',
            "<?php\nHttp::get('https://example.com');\n",
        );

        $result = (new TlsVerificationCheck($workspace))->run();

        $this->assertSame(CheckResult::PASS, $result->status);
    }

    public function test_detects_without_verifying(): void
    {
        $workspace = $this->makeWorkspace();
        $this->writeFile(
            $workspace,
            'app/Services/HttpClient.php',
            "<?php\nHttp::withoutVerifying()->get('https://example.com');\n",
        );

        $result = (new TlsVerificationCheck($workspace))->run();

        $this->assertSame(CheckResult::FAIL, $result->status);
        $this->assertStringContainsString('withoutVerifying', $result->details[0]);
    }

    public function test_detects_verify_false_option(): void
    {
        $workspace = $this->makeWorkspace();
        $this->writeFile(
            $workspace,
            'app/Services/GuzzleClient.php',
            "<?php\n\$client = new Client(['verify' => false]);\n",
        );

        $result = (new TlsVerificationCheck($workspace))->run();

        $this->assertSame(CheckResult::FAIL, $result->status);
    }

    public function test_detects_curlopt_ssl_verifypeer_disabled(): void
    {
        $workspace = $this->makeWorkspace();
        $this->writeFile(
            $workspace,
            'app/Services/CurlClient.php',
            "<?php\ncurl_setopt(\$ch, CURLOPT_SSL_VERIFYPEER, false);\n",
        );

        $result = (new TlsVerificationCheck($workspace))->run();

        $this->assertSame(CheckResult::FAIL, $result->status);
    }

    public function test_ignores_findings_under_tests(): void
    {
        $workspace = $this->makeWorkspace();
        $this->writeFile(
            $workspace,
            'tests/Unit/HttpTest.php',
            "<?php\nHttp::withoutVerifying()->get('https://example.com');\n",
        );

        $result = (new TlsVerificationCheck($workspace))->run();

        $this->assertSame(CheckResult::PASS, $result->status);
    }

    public function test_name_is_stable(): void
    {
        $this->assertSame(
            'TLS Certificate Verification',
            (new TlsVerificationCheck($this->makeWorkspace()))->name(),
        );
    }
}
