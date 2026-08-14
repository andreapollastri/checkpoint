<?php

namespace Checkpoint\Tests\Unit;

use Checkpoint\Checks\CheckResult;
use Checkpoint\Tests\TestCase;

class CheckResultTest extends TestCase
{
    public function test_pass_factory_builds_a_passing_result(): void
    {
        $result = CheckResult::pass('all good');

        $this->assertSame(CheckResult::PASS, $result->status);
        $this->assertSame('all good', $result->message);
        $this->assertSame([], $result->details);
    }

    public function test_warn_factory_builds_a_warning_result_with_details(): void
    {
        $result = CheckResult::warn('careful', ['one', 'two']);

        $this->assertSame(CheckResult::WARN, $result->status);
        $this->assertSame('careful', $result->message);
        $this->assertSame(['one', 'two'], $result->details);
    }

    public function test_fail_factory_builds_a_failing_result(): void
    {
        $result = CheckResult::fail('broken', ['detail']);

        $this->assertSame(CheckResult::FAIL, $result->status);
        $this->assertSame('broken', $result->message);
        $this->assertSame(['detail'], $result->details);
        $this->assertSame([], $result->hashes);
    }

    public function test_factory_accepts_optional_per_detail_hashes(): void
    {
        $result = CheckResult::fail('broken', ['detail'], ['detail' => 'abc123def456']);

        $this->assertSame(['detail' => 'abc123def456'], $result->hashes);
        $this->assertSame('abc123def456', $result->hashFor('Some Check', 'detail'));
    }

    public function test_hash_finding_strips_line_numbers_before_emdash(): void
    {
        $withLine = CheckResult::hashFinding('Hardcoded Secrets', "app/Foo.php:14 — secret");
        $withoutLine = CheckResult::hashFinding('Hardcoded Secrets', "app/Foo.php — secret");

        $this->assertSame($withoutLine, $withLine);
        $this->assertSame(12, strlen($withLine));
    }

    public function test_hash_for_falls_back_to_hashing_the_detail_text(): void
    {
        $result = CheckResult::fail('broken', ['fresh detail']);

        $this->assertSame(
            CheckResult::hashFinding('Some Check', 'fresh detail'),
            $result->hashFor('Some Check', 'fresh detail'),
        );
    }

    public function test_status_constants_are_distinct(): void
    {
        $this->assertSame('pass', CheckResult::PASS);
        $this->assertSame('warn', CheckResult::WARN);
        $this->assertSame('fail', CheckResult::FAIL);
    }

    public function test_properties_are_readonly(): void
    {
        $result = CheckResult::pass('x');

        $this->expectException(\Error::class);

        /** @phpstan-ignore-next-line — intentionally violating readonly for the test */
        $result->status = 'mutated';
    }
}
