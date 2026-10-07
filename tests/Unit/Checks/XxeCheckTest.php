<?php

namespace Checkpoint\Tests\Unit\Checks;

use Checkpoint\Checks\CheckResult;
use Checkpoint\Checks\XxeCheck;
use Checkpoint\Tests\TestCase;

class XxeCheckTest extends TestCase
{
    public function test_passes_on_default_xml_parsing(): void
    {
        $result = $this->scan(
            "<?php\n\$doc = new DOMDocument();\n\$doc->loadXML(\$xml, LIBXML_NONET);\nsimplexml_load_string(\$xml);\n",
        );

        $this->assertSame(CheckResult::PASS, $result->status);
    }

    public function test_detects_libxml_noent(): void
    {
        $result = $this->scan("<?php\n\$doc->loadXML(\$request->getContent(), LIBXML_NOENT);\n");

        $this->assertSame(CheckResult::FAIL, $result->status);
        $this->assertStringStartsWith('app/Services/XmlImporter.php:2 — LIBXML_NOENT', $result->details[0]);
    }

    public function test_detects_dtd_loading_flags(): void
    {
        $result = $this->scan("<?php\nsimplexml_load_string(\$xml, 'SimpleXMLElement', LIBXML_DTDLOAD | LIBXML_DTDATTR);\n");

        $this->assertSame(CheckResult::FAIL, $result->status);
        $this->assertCount(1, $result->details);
    }

    public function test_detects_entity_loader_and_dom_properties(): void
    {
        $result = $this->scan(implode("\n", [
            '<?php',
            'libxml_disable_entity_loader(false);',
            '$doc->substituteEntities = true;',
            '$doc->resolveExternals = true;',
            '$reader->setParserProperty(XMLReader::SUBST_ENTITIES, true);',
        ]));

        $this->assertSame(CheckResult::FAIL, $result->status);
        $this->assertCount(4, $result->details);
    }

    public function test_ignores_comments(): void
    {
        $result = $this->scan("<?php\n// never pass LIBXML_NOENT here\n * LIBXML_DTDLOAD is unsafe\n");

        $this->assertSame(CheckResult::PASS, $result->status);
    }

    private function scan(string $contents): CheckResult
    {
        $workspace = $this->makeWorkspace();
        $this->writeFile($workspace, 'app/Services/XmlImporter.php', $contents);

        return (new XxeCheck($workspace))->run();
    }
}
