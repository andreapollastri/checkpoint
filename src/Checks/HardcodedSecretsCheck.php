<?php

namespace Checkpoint\Checks;

use Symfony\Component\Finder\Finder;

class HardcodedSecretsCheck extends AbstractCheck
{
    // Matches assignment of secret-sounding keys to literal string values
    private const PATTERNS = [
        // Array key => 'literal value'  or  ->method('literal')  for secret-named keys
        '/["\'](?:password|passwd|pwd|secret|api_key|apikey|api_secret|token|auth_token|access_token|private_key|client_secret|app_secret|webhook_secret|refresh_token|bearer|authorization|gitlab_token|gitlab_pat|google_api_key|gcp_key|paypal_secret|paypal_client_secret|stripe_key|twilio_token|sendgrid_key|mailgun_key|slack_token|discord_token|notion_token|openai_key|openai_api_key|anthropic_key|anthropic_api_key|claude_api_key|claude_key|mistral_api_key|groq_api_key|replicate_api_key|replicate_token|huggingface_token|hf_token|perplexity_api_key|together_api_key|gemini_api_key|vertex_api_key|openrouter_api_key|fireworks_api_key|xai_api_key|grok_api_key|elevenlabs_api_key|elevenlabs_apikey|cohere_api_key|langchain_api_key|langsmith_api_key|langfuse_secret_key|langfuse_public_key|voyage_api_key|jina_api_key|databricks_token|npm_token|pypi_token|shopify_token|mapbox_token|square_token|firebase_key|oauth_secret|signing_secret|encryption_key|db_password|database_password)["\']\s*=>\s*["\'][^"\']{4,}["\']/i',
        // $variable = 'literal' where variable name looks like a secret
        '/\$(?:password|secret|api_key|apikey|token|access_token|private_key|client_secret|gitlab_token|google_api_key|paypal_secret|refresh_token|webhook_secret|anthropic_key|claude_key|openai_key|groq_key|mistral_key|hf_token|replicate_token|perplexity_key|langsmith_key|langfuse_secret)\s*=\s*["\'][^"\']{4,}["\']/i',
        // AWS access keys
        '/AKIA[0-9A-Z]{16}/',
        // PEM private key headers in source code
        '/-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----/',
        // Stripe live/test secret keys
        '/sk_(?:live|test)_[0-9a-zA-Z]{24,}/',
        // Generic Bearer tokens assigned literally
        '/["\']Bearer\s+[A-Za-z0-9\-._~+\/]{20,}["\']/',
        // GitHub (classic PAT, fine-grained, OAuth app)
        '/ghp_[A-Za-z0-9]{36}/',
        '/github_pat_[A-Za-z0-9_]{20,}/',
        '/gho_[A-Za-z0-9]{36}/',
        '/ghu_[A-Za-z0-9]{36}/',
        '/ghs_[A-Za-z0-9]{36}/',
        '/ghr_[A-Za-z0-9]{36}/',
        // Slack tokens
        '/xox[baprs]-[0-9A-Za-z\-]{10,}/',
        // GitLab (PAT, deploy, CI job, runner registration — routable tokens may contain dots)
        '/gl(?:pat|cbt|dt|rt)-[A-Za-z0-9_.-]{20,}/',
        // Google API keys & OAuth client secrets
        '/AIza[0-9A-Za-z\-_]{35}/',
        '/GOCSPX-[A-Za-z0-9_-]{20,}/',
        '/ya29\.[A-Za-z0-9_-]+/',
        // PayPal / Braintree (webhook id, classic token path, Braintree keys)
        '/WH-[0-9A-Z][A-Za-z0-9-]{10,}/',
        '/access_token\\\$production\\\$/',
        '/access_token\\\$sandbox\\\$/',
        '/access_token\$production\$/',
        '/access_token\$sandbox\$/',
        // OpenAI (legacy body marker), project keys, OpenRouter
        '/sk-[A-Za-z0-9]+T3BlbkFJ[A-Za-z0-9]+/',
        '/\bsk-[A-Za-z0-9]{45,}\b/',
        '/sk-proj-[A-Za-z0-9_-]{20,}/',
        '/sk-or-v1-[A-Za-z0-9_-]{20,}/',
        // Anthropic / Claude (api, admin, workspace keys — single sk-ant- family)
        '/sk-ant-[A-Za-z0-9_-]{10,}/',
        // Cohere, Groq, Replicate, Hugging Face, Perplexity, xAI Grok, Fireworks
        '/cg_[A-Za-z0-9]{20,}/',
        '/gsk_[A-Za-z0-9]{20,}/',
        '/\br8_[A-Za-z0-9]{30,}\b/',
        '/\bhf_[A-Za-z0-9]{30,}\b/',
        '/pplx-[A-Za-z0-9_-]{20,}/',
        '/xai-[A-Za-z0-9_-]{20,}/',
        '/fw_[A-Za-z0-9_-]{20,}/',
        // Voyage (embeddings) / Jina AI
        '/pa-[A-Za-z0-9_-]{30,}/',
        '/jina_[A-Za-z0-9_-]{20,}/',
        // Langfuse (LLM observability) / LangSmith (LangChain)
        '/sk-lf-[A-Za-z0-9_-]{20,}/',
        '/lsv2_(?:pt|sk)_[A-Za-z0-9_-]{20,}/',
        // npm / PyPI / Rubygems
        '/npm_[A-Za-z0-9]{36,}/',
        '/pypi-AgE[Ii][0-9A-Za-z_-]{50,}/',
        '/rubygems_[A-Za-z0-9]{48,}/',
        // Twilio / SendGrid / Mailgun
        '/SK[0-9a-f]{32}/',
        '/AC[0-9a-f]{32}/',
        '/SG\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}/',
        '/key-[0-9a-fA-F]{32}/',
        // Shopify / Square / Mapbox / Dropbox / Asana
        '/shp(?:at|ss|ca|pa)_[a-fA-F0-9]{32}/',
        '/sq0(?:csp|atp|idp)-[A-Za-z0-9_-]{10,}/',
        '/(?:pk|sk)\.[a-zA-Z0-9]{60,}/',
        '/sl\.[A-Za-z0-9_-]{10,}-[A-Za-z0-9_-]{10,}/',
        '/[0-9]{10,}\/[0-9]:[a-f0-9]{32}:/',
        // Discord / Telegram / Twitch
        '/\b(?:[MN][A-Za-z\d]{23}|[A-Za-z\d]{23,28})\.[A-Za-z\d-]{6}\.[A-Za-z\d_-]{27,}\b/',
        '/\d{8,10}:[A-Za-z0-9_-]{35}/',
        '/oauth:[a-z0-9]{30,}/i',
        // Notion / Linear / Databricks / New Relic / Sentry DSN fragment
        '/\bsecret_[A-Za-z0-9]{40,}\b/',
        '/lin_api_[A-Za-z0-9]{20,}/',
        '/dapi[a-f0-9]{32}/',
        '/NRAK-[A-Z0-9]{27}/',
        '/[a-f0-9]{32}@o[0-9]+\.ingest\.(?:de\.)?sentry\.io/',
        // Cloudinary URL with embedded credentials
        '/cloudinary:\/\/[0-9]+:[^@"\s]+@[a-z0-9.-]+/i',
        // DigitalOcean personal access token
        '/dop_v1_[a-f0-9]{64}/',
        // HubSpot private app token (region prefix + UUID-shaped segments)
        '/pat-(?:eu1|na1)-[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}/',
        // Facebook / LinkedIn long-lived tokens (distinctive prefix)
        '/EAA[a-zA-Z0-9]{20,}/',
        // Mailchimp API key (datacenter suffix)
        '/[a-f0-9]{32}-us[0-9]{1,2}\b/',
        // Generic private RSA material in JSON (Google service accounts, etc.)
        '/"private_key"\s*:\s*"-----BEGIN/',
    ];

    private const EXCLUDE_PATHS = [
        'vendor',
        'node_modules',
        'storage',
        'bootstrap/cache',
        '.git',
        'tests',
    ];

    // Files under these paths contain intentionally fake/placeholder values
    private const LANG_ROOTS = [
        'lang/',
        'resources/lang/',
    ];

    private const FACTORY_ROOT = 'database/factories/';

    // Migrations, seeders, and factories are dev-time / known test data, not app secrets
    private const DATABASE_ROOT = 'database/';

    private const SAFE_FUNCTIONS = [
        'env(',
        'config(',
        'getenv(',
    ];

    public function __construct(private readonly string $basePath) {}

    public function name(): string
    {
        return 'Hardcoded Secrets';
    }

    public function run(): CheckResult
    {
        $finder = new Finder;
        $finder->files()
            ->in($this->basePath)
            ->name(['*.php', '*.js', '*.ts', '.env.example'])
            ->notPath(self::EXCLUDE_PATHS)
            ->notName('.env');

        // FAIL-level: real source code with hardcoded secrets
        $failures = [];
        // WARN-level: factory files use fake credentials by design
        $warnings = [];

        foreach ($finder as $file) {
            $lines = explode("\n", $file->getContents());
            $relative = ltrim(str_replace($this->basePath, '', $file->getRealPath()), '/');

            // Lang files contain UI strings like 'password' => 'Wrong password.' — always skip
            if ($this->isLangFile($relative)) {
                continue;
            }

            if ($this->isDatabaseFile($relative)) {
                continue;
            }

            $isFactory = $this->isFactoryFile($relative);

            foreach ($lines as $i => $line) {
                $trimmed = trim($line);

                if ($trimmed === '' || str_starts_with($trimmed, '//') || str_starts_with($trimmed, '#')) {
                    continue;
                }

                foreach (self::PATTERNS as $pattern) {
                    if (! preg_match($pattern, $line)) {
                        continue;
                    }

                    // Skip lines that fetch the value from env/config at runtime
                    $isSafe = false;
                    foreach (self::SAFE_FUNCTIONS as $fn) {
                        if (str_contains($line, $fn)) {
                            $isSafe = true;
                            break;
                        }
                    }

                    if (! $isSafe && $this->isLaravelPasswordHashedCast($line)) {
                        $isSafe = true;
                    }

                    if (! $isSafe && $this->isValidationRule($line)) {
                        $isSafe = true;
                    }

                    if (! $isSafe) {
                        $entry = "{$relative}:".($i + 1).' — '.mb_strimwidth($trimmed, 0, 120, '…');
                        if ($isFactory) {
                            $warnings[] = $entry;
                        } else {
                            $failures[] = $entry;
                        }
                        break;
                    }
                }
            }
        }

        if (empty($failures) && empty($warnings)) {
            return CheckResult::pass('No hardcoded secrets detected.');
        }

        // Failures take precedence; factory warnings are appended with a prefix so they remain visible
        if (! empty($failures)) {
            $details = $failures;
            if (! empty($warnings)) {
                $details[] = '— factory files (expected, but review if values look real):';
                foreach ($warnings as $w) {
                    $details[] = '  [factory] '.$w;
                }
            }

            return CheckResult::fail(count($failures).' potential hardcoded secret(s) found.', $details);
        }

        return CheckResult::warn(
            count($warnings).' hardcoded value(s) in factory file(s) — ensure they are fake/seeded data only.',
            $warnings
        );
    }

    private function isLangFile(string $relativePath): bool
    {
        foreach (self::LANG_ROOTS as $root) {
            if (str_starts_with($relativePath, $root)) {
                return true;
            }
        }

        return false;
    }

    private function isFactoryFile(string $relativePath): bool
    {
        return str_starts_with($relativePath, self::FACTORY_ROOT);
    }

    private function isDatabaseFile(string $relativePath): bool
    {
        return str_starts_with($relativePath, self::DATABASE_ROOT);
    }

    /**
     * Laravel 11+ password cast: 'password' => 'hashed' in casts() — not a secret.
     */
    private function isLaravelPasswordHashedCast(string $line): bool
    {
        return (bool) preg_match('/[\'"]password[\'"]\s*=>\s*[\'"]hashed[\'"]/i', $line);
    }

    private function isValidationRule(string $line): bool
    {
        return (bool) preg_match(
            '/=>\s*["\'](?:required|nullable|sometimes|present|prohibited|accepted|email|string|integer|numeric|uuid|url|json|file|image|confirmed|min:|max:|regex:|in:|not_in:|unique:|exists:)[^"\']*["\']/i',
            $line
        );
    }
}
