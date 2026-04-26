<?php

namespace Checkpoint\Checks;

abstract class AbstractCheck
{
    abstract public function name(): string;

    abstract public function run(): CheckResult;
}
