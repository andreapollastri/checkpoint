<?php

use Checkpoint\Checks\CheckResult;

it('builds a passing result', function () {
    $result = CheckResult::pass('all good');

    expect($result->status)->toBe(CheckResult::PASS)
        ->and($result->message)->toBe('all good')
        ->and($result->details)->toBe([]);
});

it('builds a warning result with details', function () {
    $result = CheckResult::warn('careful', ['first', 'second']);

    expect($result->status)->toBe(CheckResult::WARN)
        ->and($result->message)->toBe('careful')
        ->and($result->details)->toBe(['first', 'second']);
});

it('builds a failing result with details', function () {
    $result = CheckResult::fail('boom', ['detail']);

    expect($result->status)->toBe(CheckResult::FAIL)
        ->and($result->message)->toBe('boom')
        ->and($result->details)->toBe(['detail']);
});
