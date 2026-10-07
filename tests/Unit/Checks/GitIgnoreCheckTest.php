<?php

namespace Checkpoint\Tests\Unit\Checks;

use Checkpoint\Checks\CheckResult;
use Checkpoint\Checks\GitIgnoreCheck;
use Checkpoint\Tests\TestCase;

class GitIgnoreCheckTest extends TestCase
{
    public function test_passes_with_the_default_laravel_gitignore(): void
    {
        $workspace = $this->makeWorkspace();
        $this->writeFile($workspace, '.gitignore', implode("\n", [
            '/storage/*.key',
            '/storage/logs',
            '.env',
            '.env.backup',
            '.env.production',
            '*.pem',
            'auth.json',
        ]));

        $result = (new GitIgnoreCheck($workspace))->run();

        $this->assertSame(CheckResult::PASS, $result->status);
    }

    public function test_warns_when_composer_auth_json_is_not_ignored(): void
    {
        $workspace = $this->makeWorkspace();
        $this->writeFile($workspace, '.gitignore', ".env\n.env.backup\n.env.production\n*.key\n*.pem\nstorage/logs\n");

        $result = (new GitIgnoreCheck($workspace))->run();

        $this->assertSame(CheckResult::WARN, $result->status);
        $this->assertSame(['"auth.json" is not listed in .gitignore.'], $result->details);
    }
}
