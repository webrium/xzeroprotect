<?php

declare(strict_types=1);

use PHPUnit\Framework\TestCase;
use Webrium\XZeroProtect\BotDetector;
use Webrium\XZeroProtect\VisitInfo;
use Webrium\XZeroProtect\XZeroProtect;

class BotDetectionTest extends TestCase
{
    private string $tmpDir;

    /** @var array<int,VisitInfo> */
    private array $recorded = [];

    private const CHROME  = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36';
    private const PULSETIC = 'Pulsetic/1.0 (+https://pulsetic.com)';
    private const GPTBOT  = 'Mozilla/5.0 AppleWebKit/537.36 (KHTML, like Gecko; compatible; GPTBot/1.1; +https://openai.com/gptbot)';

    protected function setUp(): void
    {
        $this->tmpDir   = sys_get_temp_dir() . '/xzp_bots_' . uniqid();
        $this->recorded = [];
        mkdir($this->tmpDir, 0755, true);

        $_SERVER['REMOTE_ADDR']     = '203.0.113.10';
        $_SERVER['REQUEST_METHOD']  = 'GET';
        $_SERVER['REQUEST_URI']     = '/blog/how-to-build-a-cms';
        $_SERVER['HTTP_USER_AGENT'] = self::CHROME;
        $_GET = $_POST = $_COOKIE = [];

        foreach (['HTTP_SEC_FETCH_DEST', 'HTTP_X_REQUESTED_WITH', 'HTTP_SEC_PURPOSE'] as $header) {
            unset($_SERVER[$header]);
        }
    }

    protected function tearDown(): void
    {
        $this->removeDir($this->tmpDir);
    }

    private function detector(array $extra = []): BotDetector
    {
        return new BotDetector(dirname(__DIR__) . '/rules', $extra);
    }

    private function runAs(string $userAgent, array $tracking = []): XZeroProtect
    {
        $_SERVER['HTTP_USER_AGENT'] = $userAgent;

        $firewall = XZeroProtect::init([
            'storage_path' => $this->tmpDir,
            'tracking'     => $tracking,
        ]);

        $firewall->enableTracking(function (VisitInfo $visit) {
            $this->recorded[] = $visit;
        });

        $firewall->run();

        return $firewall;
    }

    private function removeDir(string $dir): void
    {
        if (!is_dir($dir)) {
            return;
        }

        foreach (scandir($dir) ?: [] as $entry) {
            if ($entry === '.' || $entry === '..') {
                continue;
            }

            $path = $dir . '/' . $entry;
            is_dir($path) ? $this->removeDir($path) : @unlink($path);
        }

        @rmdir($dir);
    }

    // =========================================================================
    // People are never labelled as bots
    // =========================================================================

    /**
     * @dataProvider browsers
     */
    public function test_real_browsers_are_not_bots(string $userAgent): void
    {
        $this->assertNull($this->detector()->detect($userAgent));
    }

    public static function browsers(): array
    {
        return [
            'chrome windows'  => [self::CHROME],
            'firefox linux'   => ['Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:125.0) Gecko/20100101 Firefox/125.0'],
            'safari macos'    => ['Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Safari/605.1.15'],
            'safari iphone'   => ['Mozilla/5.0 (iPhone; CPU iPhone OS 17_4 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Mobile/15E148 Safari/604.1'],
            'chrome android'  => ['Mozilla/5.0 (Linux; Android 14; SM-S918B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Mobile Safari/537.36'],
            'edge'            => ['Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36 Edg/124.0.0.0'],
            'samsung browser' => ['Mozilla/5.0 (Linux; Android 13; SAMSUNG SM-A546B) AppleWebKit/537.36 (KHTML, like Gecko) SamsungBrowser/24.0 Chrome/117.0.0.0 Mobile Safari/537.36'],
            'opera mini'      => ['Opera/9.80 (Android; Opera Mini/36.2.2254/119.132; U; en) Presto/2.12.423 Version/12.16'],
            'facebook in-app' => ['Mozilla/5.0 (iPhone; CPU iPhone OS 17_4 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Mobile/15E148 [FBAN/FBIOS;FBAV/450.0.0.0;FBBV/1;FBDV/iPhone14,2]'],
            'instagram app'   => ['Mozilla/5.0 (iPhone; CPU iPhone OS 17_4 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Mobile/15E148 Instagram 330.0.0.0'],
            'cubot phone'     => ['Mozilla/5.0 (Linux; Android 9; CUBOT X19) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/99.0.4844.88 Mobile Safari/537.36'],
            'cubot underscore'=> ['Mozilla/5.0 (Linux; Android 9; CUBOT_X19) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/99.0.4844.88 Mobile Safari/537.36'],
            'persian browser' => ['Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36 OPR/110.0.0.0'],
        ];
    }

    // =========================================================================
    // Bots are named
    // =========================================================================

    /**
     * @dataProvider bots
     */
    public function test_bots_are_detected_and_named(string $userAgent, string $label): void
    {
        $this->assertSame($label, $this->detector()->detect($userAgent));
    }

    public static function bots(): array
    {
        return [
            'pulsetic'        => [self::PULSETIC, 'Pulsetic'],
            'uptimerobot'     => ['Mozilla/5.0+(compatible; UptimeRobot/2.0; http://www.uptimerobot.com/)', 'UptimeRobot'],
            'curl'            => ['curl/8.5.0', 'curl'],
            'python'          => ['python-requests/2.31.0', 'python-requests'],
            'go client'       => ['Go-http-client/2.0', 'Go-http-client'],
            'headless chrome' => ['Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) HeadlessChrome/124.0.0.0 Safari/537.36', 'HeadlessChrome'],
            'chatgpt-user'    => ['Mozilla/5.0 AppleWebKit/537.36 (KHTML, like Gecko); compatible; ChatGPT-User/1.0; +https://openai.com/bot', 'ChatGPT'],
            'googlebot'       => ['Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)', 'Googlebot'],
            'ahrefs'          => ['Mozilla/5.0 (compatible; AhrefsBot/7.0; +http://ahrefs.com/robot/)', 'AhrefsBot'],
            'mj12'            => ['Mozilla/5.0 (compatible; MJ12bot/v1.4.8; http://mj12bot.com/)', 'MJ12bot'],
            'bytespider'      => ['Mozilla/5.0 (Linux; Android 5.0) AppleWebKit/537.36 (KHTML, like Gecko) Mobile Safari/537.36 (compatible; Bytespider; spider-feedback@bytedance.com)', 'Bytespider'],
            'facebook fetch'  => ['facebookexternalhit/1.1 (+http://www.facebook.com/externalhit_uatext.php)', 'Facebook'],
            'slurp'           => ['Mozilla/5.0 (compatible; Yahoo! Slurp; http://help.yahoo.com/help/us/ysearch/slurp)', 'Yahoo Slurp'],
            'url in ua'       => ['Mozilla/5.0 (compatible; SiteChecker 1.0; +https://example.com/about)', 'Bot (URL in User-Agent)'],
            'empty'           => ['', 'Empty User-Agent'],
            'blank'           => ['   ', 'Empty User-Agent'],
            'non-browser'     => ['MyCustomApp/3.2', 'Non-browser client'],
        ];
    }

    public function test_is_bot_mirrors_detect(): void
    {
        $detector = $this->detector();

        $this->assertTrue($detector->isBot(self::PULSETIC));
        $this->assertFalse($detector->isBot(self::CHROME));
    }

    // =========================================================================
    // Customising
    // =========================================================================

    public function test_extra_agents_from_the_constructor(): void
    {
        $detector = $this->detector(['internal-probe', 'acme-scanner' => 'Acme Scanner']);
        $ua       = 'Mozilla/5.0 (X11) internal-probe/1';

        $this->assertSame('internal-probe', $detector->detect($ua));
        $this->assertSame('Acme Scanner', $detector->detect('Mozilla/5.0 acme-scanner'));
    }

    public function test_agent_can_be_added_and_removed(): void
    {
        $detector = $this->detector();
        $ua       = 'Mozilla/5.0 (X11) Pulsetic/1';

        $this->assertSame('Pulsetic', $detector->detect($ua));

        $detector->removeAgent('pulsetic');
        $this->assertNull($detector->detect($ua));

        $detector->addAgent('pulsetic', 'Pulsetic monitor');
        $this->assertSame('Pulsetic monitor', $detector->detect($ua));
    }

    public function test_pattern_can_be_removed_and_replaced(): void
    {
        $detector = $this->detector();
        $ua       = 'Mozilla/5.0 (X11) Linux ZebraBot/1';

        $this->assertSame('ZebraBot', $detector->detect($ua));

        $rules = require dirname(__DIR__) . '/rules/bots.php';
        $detector->removePattern($rules['pattern']);
        $this->assertNull($detector->detect($ua));

        $detector->addPattern('/(zebra\w*)/i');
        $this->assertSame('ZebraBot', $detector->detect($ua));
    }

    public function test_non_browser_rule_can_be_turned_off(): void
    {
        $detector = $this->detector()->treatNonBrowserAsBot(false);

        $this->assertNull($detector->detect('MyCustomApp/3.2'));
        // Everything else still applies.
        $this->assertSame('curl', $detector->detect('curl/8.5.0'));
        $this->assertSame('Empty User-Agent', $detector->detect(''));
    }

    // =========================================================================
    // VisitInfo
    // =========================================================================

    public function test_visit_info_defaults_to_a_person(): void
    {
        $visit = new VisitInfo(new \Webrium\XZeroProtect\Request());

        $this->assertFalse($visit->isBot);
        $this->assertNull($visit->botName);
    }

    public function test_visit_info_carries_the_bot_name(): void
    {
        $visit = new VisitInfo(new \Webrium\XZeroProtect\Request(), 'Pulsetic');

        $this->assertTrue($visit->isBot);
        $this->assertSame('Pulsetic', $visit->botName);

        $row = $visit->toArray();
        $this->assertTrue($row['is_bot']);
        $this->assertSame('Pulsetic', $row['bot_name']);
    }

    public function test_to_array_for_a_person(): void
    {
        $row = (new VisitInfo(new \Webrium\XZeroProtect\Request()))->toArray();

        $this->assertFalse($row['is_bot']);
        $this->assertNull($row['bot_name']);
    }

    // =========================================================================
    // Tracking
    // =========================================================================

    public function test_people_are_tracked_and_not_flagged(): void
    {
        $this->runAs(self::CHROME);

        $this->assertCount(1, $this->recorded);
        $this->assertFalse($this->recorded[0]->isBot);
    }

    public function test_unknown_bot_is_not_tracked_by_default(): void
    {
        $this->runAs(self::PULSETIC);

        $this->assertSame([], $this->recorded);
    }

    public function test_unknown_bot_is_tracked_and_flagged_when_included(): void
    {
        $this->runAs(self::PULSETIC, ['include_bots' => true]);

        $this->assertCount(1, $this->recorded);
        $this->assertTrue($this->recorded[0]->isBot);
        $this->assertSame('Pulsetic', $this->recorded[0]->botName);
    }

    public function test_trusted_crawler_is_not_tracked_by_default(): void
    {
        $this->runAs(self::GPTBOT);

        $this->assertSame([], $this->recorded);
    }

    public function test_trusted_crawler_is_tracked_and_named_when_included(): void
    {
        $this->runAs(self::GPTBOT, ['include_bots' => true]);

        $this->assertCount(1, $this->recorded);
        $this->assertTrue($this->recorded[0]->isBot);
        $this->assertSame('OpenAI GPTBot', $this->recorded[0]->botName);
    }

    public function test_trusted_crawler_still_skips_the_firewall_checks(): void
    {
        // A crawler must stay exempt whether or not the tracker wants it.
        $_SERVER['REQUEST_URI'] = '/wp-admin/setup-config.php';

        $this->runAs(self::GPTBOT, ['include_bots' => true]);

        $this->assertCount(1, $this->recorded);
    }

    public function test_filter_off_records_everything_including_bots(): void
    {
        $this->runAs(self::PULSETIC, ['filter' => false]);

        $this->assertCount(1, $this->recorded);
        $this->assertTrue($this->recorded[0]->isBot);
    }

    public function test_filter_off_still_leaves_verified_crawlers_out_unless_asked(): void
    {
        $this->runAs(self::GPTBOT, ['filter' => false]);

        $this->assertSame([], $this->recorded);
    }

    public function test_asset_requests_from_bots_stay_out_even_when_included(): void
    {
        $_SERVER['REQUEST_URI'] = '/assets/app.css';

        $this->runAs(self::GPTBOT, ['include_bots' => true]);

        $this->assertSame([], $this->recorded);
    }

    public function test_include_bots_can_be_changed_at_runtime(): void
    {
        $firewall = $this->runAs(self::PULSETIC);
        $this->assertFalse($firewall->isIncludingBots());
        $this->assertSame([], $this->recorded);

        $firewall->includeBots();
        $this->assertTrue($firewall->isIncludingBots());

        $firewall->run();
        $this->assertCount(1, $this->recorded);
    }

    public function test_bot_agents_config_extends_the_defaults(): void
    {
        $this->runAs('Mozilla/5.0 (X11) acme-scanner/2', [
            'include_bots' => true,
            'bot_agents'   => ['acme-scanner' => 'Acme Scanner'],
        ]);

        $this->assertCount(1, $this->recorded);
        $this->assertSame('Acme Scanner', $this->recorded[0]->botName);
    }
}
