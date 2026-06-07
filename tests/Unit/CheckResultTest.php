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
