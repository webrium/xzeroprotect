<?php

declare(strict_types=1);

use PHPUnit\Framework\TestCase;
use Webrium\XZeroProtect\CrawlerVerifier;

/**
 * AI assistants fetch pages for the people asking them questions. Blocking one
 * by rate limit costs a citation, so each must be recognised.
 */
class AiCrawlerTest extends TestCase
{
    private CrawlerVerifier $crawlers;

    protected function setUp(): void
    {
        $this->crawlers = new CrawlerVerifier(dirname(__DIR__) . '/rules');
    }

    /**
     * @dataProvider aiAgents
     */
    public function test_ai_agent_is_a_trusted_crawler(string $userAgent, string $name): void
    {
        // None of these needs DNS, so the check is offline and instant.
        $this->assertTrue($this->crawlers->isTrustedCrawler('203.0.113.9', $userAgent));
        $this->assertSame($name, $this->crawlers->getCrawlerName($userAgent));
    }

    public static function aiAgents(): array
    {
        return [
            'oai searchbot'    => ['Mozilla/5.0 AppleWebKit/537.36 (KHTML, like Gecko; compatible; OAI-SearchBot/1.4; +https://openai.com/searchbot)', 'OpenAI OAI-SearchBot'],
            'oai adsbot'       => ['Mozilla/5.0 AppleWebKit/537.36 (KHTML, like Gecko; compatible; OAI-AdsBot/1.0; +https://openai.com/adsbot)', 'OpenAI OAI-AdsBot'],
            'chatgpt user'     => ['Mozilla/5.0 AppleWebKit/537.36 (KHTML, like Gecko); compatible; ChatGPT-User/1.0; +https://openai.com/bot', 'OpenAI ChatGPT-User'],
            'gptbot'           => ['Mozilla/5.0 AppleWebKit/537.36 (KHTML, like Gecko; compatible; GPTBot/1.4; +https://openai.com/gptbot)', 'OpenAI GPTBot'],
            'claude user'      => ['Mozilla/5.0 AppleWebKit/537.36 (KHTML, like Gecko; compatible; Claude-User/1.0; +Claude-User@anthropic.com)', 'Anthropic Claude-User'],
            'claude searchbot' => ['Mozilla/5.0 AppleWebKit/537.36 (KHTML, like Gecko; compatible; Claude-SearchBot/1.0; +searchbot@anthropic.com)', 'Anthropic Claude-SearchBot'],
            'claudebot'        => ['Mozilla/5.0 AppleWebKit/537.36 (KHTML, like Gecko; compatible; ClaudeBot/1.0; +claudebot@anthropic.com)', 'Anthropic ClaudeBot'],
            'perplexity user'  => ['Mozilla/5.0 AppleWebKit/537.36 (KHTML, like Gecko; compatible; Perplexity-User/1.0; +https://perplexity.ai/perplexity-user)', 'Perplexity-User'],
            'perplexitybot'    => ['Mozilla/5.0 AppleWebKit/537.36 (KHTML, like Gecko; compatible; PerplexityBot/1.0; +https://perplexity.ai/perplexitybot)', 'PerplexityBot'],
            'gemini notebook'  => ['Mozilla/5.0 (compatible; Google-GeminiNotebook)', 'Google Gemini Notebook'],
            'notebooklm'       => ['Mozilla/5.0 (compatible; Google-NotebookLM)', 'Google Notebook (former NotebookLM token)'],
            'google agent'     => ['Mozilla/5.0 (compatible; Google-Agent)', 'Google-Agent'],
        ];
    }

    public function test_google_fetchers_are_matched_before_the_generic_google_entry(): void
    {
        // 'google' needs rDNS on .google.com; a user-triggered fetcher may
        // resolve elsewhere, so the specific entries must win.
        $names = array_column($this->crawlers->getCrawlers(), 'name');

        foreach (['Google Gemini Notebook', 'Google-Agent'] as $specific) {
            $this->assertLessThan(
                array_search('Google Other (APIs, AdsBot, etc.)', $names, true),
                array_search($specific, $names, true),
                "$specific must come before Google Other"
            );
        }
    }

    public function test_googlebot_still_requires_dns_verification(): void
    {
        // Adding UA-only Google fetchers must not weaken Googlebot itself.
        $googlebot = array_values(array_filter(
            $this->crawlers->getCrawlers(),
            fn (array $c) => $c['name'] === 'Googlebot'
        ))[0];

        $this->assertTrue($googlebot['verify_rdns']);
        $this->assertSame('.googlebot.com', $googlebot['rdns_suffix']);
    }

    public function test_an_ordinary_browser_is_not_a_crawler(): void
    {
        $chrome = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36';

        $this->assertFalse($this->crawlers->isTrustedCrawler('203.0.113.9', $chrome));
    }
}
