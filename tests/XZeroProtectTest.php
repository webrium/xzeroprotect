<?php

declare(strict_types=1);

use PHPUnit\Framework\TestCase;
use Webrium\XZeroProtect\Storage;
use Webrium\XZeroProtect\IPManager;
use Webrium\XZeroProtect\PatternDetector;
use Webrium\XZeroProtect\RateLimiter;
use Webrium\XZeroProtect\RuleEngine;
use Webrium\XZeroProtect\RuleResult;
use Webrium\XZeroProtect\Request;
use Webrium\XZeroProtect\ApacheBlocker;
use Webrium\XZeroProtect\Logger;

class XZeroProtectTest extends TestCase
{
    private string  $tmpDir;
    private Storage $storage;

    protected function setUp(): void
    {
        $this->tmpDir  = sys_get_temp_dir() . '/xzp_test_' . uniqid();
        mkdir($this->tmpDir, 0755, true);
        $this->storage = new Storage($this->tmpDir);
    }

    protected function tearDown(): void
    {
        $this->removeDir($this->tmpDir);
    }

    // =========================================================================
    // Storage Tests
    // =========================================================================

    public function test_storage_directories_created(): void
    {
        $this->assertDirectoryExists($this->tmpDir . '/bans');
        $this->assertDirectoryExists($this->tmpDir . '/rate');
        $this->assertDirectoryExists($this->tmpDir . '/violations');
        $this->assertDirectoryExists($this->tmpDir . '/logs');
    }

    public function test_ban_and_is_banned(): void
    {
        $this->storage->ban('1.2.3.4', 'test', 3600);
        $this->assertTrue($this->storage->isBanned('1.2.3.4'));
    }

    public function test_unban(): void
    {
        $this->storage->ban('1.2.3.4', 'test', 3600);
        $this->storage->unban('1.2.3.4');
        $this->assertFalse($this->storage->isBanned('1.2.3.4'));
    }

    public function test_permanent_ban(): void
    {
        $this->storage->ban('5.5.5.5', 'permanent', 0);
        $this->assertTrue($this->storage->isBanned('5.5.5.5'));
    }

    public function test_expired_ban_is_not_banned(): void
    {
        // Ban with duration in the past
        $file = $this->tmpDir . '/bans/1_2_3_99.json';
        file_put_contents($file, json_encode([
            'ip'         => '1.2.3.99',
            'reason'     => 'old',
            'banned_at'  => time() - 7200,
            'expires'    => time() - 3600,
            'bans_count' => 1,
        ]));
        $s = new Storage($this->tmpDir);
        $this->assertFalse($s->isBanned('1.2.3.99'));
    }

    public function test_violation_tracking(): void
    {
        $this->storage->incrementViolation('10.0.0.1');
        $this->storage->incrementViolation('10.0.0.1');
        $count = $this->storage->incrementViolation('10.0.0.1');
        $this->assertSame(3, $count);
        $this->assertSame(3, $this->storage->getViolationCount('10.0.0.1'));
    }

    public function test_violation_reset(): void
    {
        $this->storage->incrementViolation('10.0.0.2');
        $this->storage->resetViolations('10.0.0.2');
        $this->assertSame(0, $this->storage->getViolationCount('10.0.0.2'));
    }

    public function test_rate_tracking(): void
    {
        for ($i = 0; $i < 5; $i++) {
            $this->storage->trackRequest('20.0.0.1', 60);
        }
        $count = $this->storage->getRateCount('20.0.0.1', 60);
        $this->assertSame(5, $count);
    }

    public function test_log_append(): void
    {
        $this->storage->appendLog([
            'ip' => '1.1.1.1', 'type' => 'sqli', 'uri' => '/test',
            'reason' => 'UNION SELECT', 'ua' => 'sqlmap',
        ]);
        $logs = $this->storage->readLogs(10);
        $this->assertNotEmpty($logs);
        $this->assertStringContainsString('1.1.1.1', $logs[0]);
    }

    public function test_get_all_bans(): void
    {
        $this->storage->ban('2.2.2.2', 'r1', 3600);
        $this->storage->ban('3.3.3.3', 'r2', 3600);
        $bans = $this->storage->getAllBans();
        $this->assertArrayHasKey('2.2.2.2', $bans);
        $this->assertArrayHasKey('3.3.3.3', $bans);
    }

    // =========================================================================
    // IPManager Tests
    // =========================================================================

    public function test_ip_manager_ban_and_check(): void
    {
        $manager = new IPManager($this->storage);
        $manager->ban('9.9.9.9', 'test');
        $this->assertTrue($manager->isBanned('9.9.9.9'));
    }

    public function test_ip_manager_whitelist_exact(): void
    {
        $manager = new IPManager($this->storage);
        $manager->whitelist('192.168.1.1');
        $this->assertTrue($manager->isWhitelisted('192.168.1.1'));
        $this->assertFalse($manager->isWhitelisted('192.168.1.2'));
    }

    public function test_ip_manager_whitelist_cidr_ipv4(): void
    {
        $manager = new IPManager($this->storage);
        $manager->whitelist('10.0.0.0/8');
        $this->assertTrue($manager->isWhitelisted('10.1.2.3'));
        $this->assertFalse($manager->isWhitelisted('11.0.0.1'));
    }

    public function test_ip_cidr_slash_24(): void
    {
        $manager = new IPManager($this->storage);
        $manager->whitelist('192.168.5.0/24');
        $this->assertTrue($manager->isWhitelisted('192.168.5.100'));
        $this->assertFalse($manager->isWhitelisted('192.168.6.1'));
    }

    public function test_ip_manager_unban(): void
    {
        $manager = new IPManager($this->storage);
        $manager->ban('8.8.8.8', 'test');
        $manager->unban('8.8.8.8');
        $this->assertFalse($manager->isBanned('8.8.8.8'));
    }

    public function test_ban_permanent(): void
    {
        $manager = new IPManager($this->storage);
        $manager->banPermanent('77.77.77.77', 'perm');
        $info = $manager->getBanInfo('77.77.77.77');
        $this->assertSame(0, $info['expires']);
    }

    // =========================================================================
    // PatternDetector Tests
    // =========================================================================

    private function makeDetector(): PatternDetector
    {
        $rulesDir = dirname(__DIR__) . '/rules';
        return new PatternDetector($rulesDir);
    }

    public function test_suspicious_path_wp_admin(): void
    {
        $d = $this->makeDetector();
        $this->assertTrue($d->isSuspiciousPath('/wp-admin/'));
    }

    public function test_suspicious_path_env(): void
    {
        $d = $this->makeDetector();
        $this->assertTrue($d->isSuspiciousPath('/.env'));
    }

    public function test_suspicious_path_php_extension(): void
    {
        $d = $this->makeDetector();
        $this->assertTrue($d->isSuspiciousPath('/index.php'));
    }

    public function test_clean_path_passes(): void
    {
        $d = $this->makeDetector();
        $this->assertFalse($d->isSuspiciousPath('/products/shoes'));
    }

    public function test_add_custom_path(): void
    {
        $d = $this->makeDetector();
        $d->addPath('/secret-panel');
        $this->assertTrue($d->isSuspiciousPath('/secret-panel/login'));
    }

    public function test_remove_path(): void
    {
        $d = $this->makeDetector();
        $d->removePath('.php');
        $this->assertFalse($d->isSuspiciousPath('/index.php'));
    }

    public function test_suspicious_agent_sqlmap(): void
    {
        $d = $this->makeDetector();
        $this->assertTrue($d->isSuspiciousAgent('sqlmap/1.6'));
    }

    public function test_empty_agent_is_suspicious(): void
    {
        $d = $this->makeDetector();
        $this->assertTrue($d->isSuspiciousAgent(''));
    }

    public function test_clean_agent_passes(): void
    {
        $d = $this->makeDetector();
        $this->assertFalse($d->isSuspiciousAgent('Mozilla/5.0 (Windows NT 10.0) Chrome/120'));
    }

    public function test_add_custom_agent(): void
    {
        $d = $this->makeDetector();
        $d->addAgent('evilbot');
        $this->assertTrue($d->isSuspiciousAgent('EvilBot/2.0'));
    }

    public function test_payload_sqli_union(): void
    {
        $d = $this->makeDetector();
        $this->assertSame('sqli_union', $d->detectPayload("1 UNION SELECT * FROM users"));
    }

    public function test_payload_xss_script(): void
    {
        $d = $this->makeDetector();
        $this->assertNotNull($d->detectPayload('<script>alert(1)</script>'));
    }

    public function test_payload_path_traversal(): void
    {
        $d = $this->makeDetector();
        $this->assertSame('traversal', $d->detectPayload('../../etc/passwd'));
    }

    public function test_clean_payload_passes(): void
    {
        $d = $this->makeDetector();
        $this->assertNull($d->detectPayload('Hello World, this is a normal search query'));
    }

    public function test_add_custom_payload(): void
    {
        $d = $this->makeDetector();
        $d->addPayload('/CUSTOM_ATTACK/i', 'my_attack');
        $this->assertSame('my_attack', $d->detectPayload('CUSTOM_ATTACK payload'));
    }

    public function test_remove_payload(): void
    {
        $d = $this->makeDetector();
        $d->removePayload('sqli_union');
        $this->assertNull($d->detectPayload('1 UNION SELECT * FROM users'));
    }

    // =========================================================================
    // RateLimiter Tests
    // =========================================================================

    public function test_rate_limit_not_exceeded(): void
    {
        $rl = new RateLimiter($this->storage, 10, 60);
        for ($i = 0; $i < 5; $i++) {
            $exceeded = $rl->isExceeded('30.0.0.1');
        }
        $this->assertFalse($exceeded);
    }

    public function test_rate_limit_exceeded(): void
    {
        $rl = new RateLimiter($this->storage, 3, 60);
        $exceeded = false;
        for ($i = 0; $i < 10; $i++) {
            $exceeded = $rl->isExceeded('30.0.0.2');
        }
        $this->assertTrue($exceeded);
    }

    // =========================================================================
    // RuleEngine Tests
    // =========================================================================

    public function test_rule_engine_pass(): void
    {
        $engine = new RuleEngine();
        $engine->add('always-pass', fn($r) => RuleResult::pass());

        // Simulate request
        $_SERVER['REMOTE_ADDR']     = '1.1.1.1';
        $_SERVER['REQUEST_URI']     = '/';
        $_SERVER['REQUEST_METHOD']  = 'GET';
        $_SERVER['HTTP_USER_AGENT'] = 'Test';
        $req = new Request();

        $result = $engine->evaluate($req);
        $this->assertTrue($result->isPass());
    }

    public function test_rule_engine_block(): void
    {
        $engine = new RuleEngine();
        $engine->add('always-block', fn($r) => RuleResult::block('testing'));

        $_SERVER['REMOTE_ADDR']     = '1.1.1.1';
        $_SERVER['REQUEST_URI']     = '/';
        $_SERVER['REQUEST_METHOD']  = 'GET';
        $_SERVER['HTTP_USER_AGENT'] = 'Test';
        $req = new Request();

        $result = $engine->evaluate($req);
        $this->assertTrue($result->isBlock());
        $this->assertSame('testing', $result->reason);
    }

    public function test_rule_engine_disable(): void
    {
        $engine = new RuleEngine();
        $engine->add('will-be-disabled', fn($r) => RuleResult::block('disabled'));
        $engine->disable('will-be-disabled');

        $_SERVER['REMOTE_ADDR']     = '1.1.1.1';
        $_SERVER['REQUEST_URI']     = '/';
        $_SERVER['REQUEST_METHOD']  = 'GET';
        $_SERVER['HTTP_USER_AGENT'] = 'Test';
        $req = new Request();

        $result = $engine->evaluate($req);
        $this->assertTrue($result->isPass());
    }

    public function test_rule_priority(): void
    {
        $log = [];
        $engine = new RuleEngine();
        $engine->add('low-priority',  function($r) use (&$log) { $log[] = 'low';  return RuleResult::pass(); }, 100);
        $engine->add('high-priority', function($r) use (&$log) { $log[] = 'high'; return RuleResult::pass(); }, 1);

        $_SERVER['REMOTE_ADDR']     = '1.1.1.1';
        $_SERVER['REQUEST_URI']     = '/';
        $_SERVER['REQUEST_METHOD']  = 'GET';
        $_SERVER['HTTP_USER_AGENT'] = 'Test';
        $req = new Request();

        $engine->evaluate($req);
        $this->assertSame(['high', 'low'], $log);
    }

    // =========================================================================
    // ApacheBlocker Tests
    // =========================================================================

    public function test_apache_blocker_creates_block(): void
    {
        $htFile = $this->tmpDir . '/.htaccess';
        touch($htFile);

        $blocker = new ApacheBlocker($htFile);
        $blocker->sync(['1.2.3.4', '5.6.7.8']);

        $content = file_get_contents($htFile);
        $this->assertStringContainsString('Require not ip 1.2.3.4', $content);
        $this->assertStringContainsString('Require not ip 5.6.7.8', $content);
        $this->assertStringContainsString('xZeroProtect:start', $content);
        $this->assertStringContainsString('xZeroProtect:end', $content);
    }

    public function test_apache_blocker_single_block(): void
    {
        $htFile = $this->tmpDir . '/.htaccess';
        touch($htFile);

        $blocker = new ApacheBlocker($htFile);
        $blocker->block('9.9.9.9');

        $content = file_get_contents($htFile);
        $this->assertStringContainsString('Require not ip 9.9.9.9', $content);
    }

    public function test_apache_blocker_unblock(): void
    {
        $htFile = $this->tmpDir . '/.htaccess';
        touch($htFile);

        $blocker = new ApacheBlocker($htFile);
        $blocker->sync(['1.1.1.1', '2.2.2.2']);
        $blocker->unblock('1.1.1.1');

        $content = file_get_contents($htFile);
        $this->assertStringNotContainsString('Require not ip 1.1.1.1', $content);
        $this->assertStringContainsString('Require not ip 2.2.2.2', $content);
    }

    public function test_apache_blocker_clear(): void
    {
        $htFile = $this->tmpDir . '/.htaccess';
        touch($htFile);

        $blocker = new ApacheBlocker($htFile);
        $blocker->sync(['1.1.1.1']);
        $blocker->clear();

        $content = file_get_contents($htFile);
        $this->assertStringNotContainsString('xZeroProtect:start', $content);
    }

    public function test_apache_blocker_does_not_duplicate(): void
    {
        $htFile = $this->tmpDir . '/.htaccess';
        touch($htFile);

        $blocker = new ApacheBlocker($htFile);
        $blocker->sync(['1.1.1.1']);
        $blocker->sync(['1.1.1.1', '2.2.2.2']);

        $content = file_get_contents($htFile);
        // Should only appear once
        $this->assertSame(1, substr_count($content, 'xZeroProtect:start'));
    }

    // =========================================================================
    // Logger Tests
    // =========================================================================

    public function test_logger_writes_and_reads(): void
    {
        $logger = new Logger($this->storage);

        $_SERVER['REMOTE_ADDR']     = '4.4.4.4';
        $_SERVER['REQUEST_URI']     = '/attack';
        $_SERVER['REQUEST_METHOD']  = 'GET';
        $_SERVER['HTTP_USER_AGENT'] = 'nikto';
        $req = new Request();

        $logger->log('user_agent', $req, 'nikto detected');
        $logs = $logger->recent(5);
        $this->assertNotEmpty($logs);
        $this->assertStringContainsString('4.4.4.4', $logs[0]);
    }

    public function test_logger_disabled_writes_nothing(): void
    {
        $logger = new Logger($this->storage, enabled: false);

        $_SERVER['REMOTE_ADDR']     = '5.5.5.5';
        $_SERVER['REQUEST_URI']     = '/x';
        $_SERVER['REQUEST_METHOD']  = 'GET';
        $_SERVER['HTTP_USER_AGENT'] = 'test';
        $req = new Request();

        $logger->log('test', $req, 'reason');
        $logs = $logger->recent(5);
        $this->assertEmpty($logs);
    }

    // =========================================================================
    // Helpers
    // =========================================================================

    private function removeDir(string $path): void
    {
        if (!is_dir($path)) return;
        foreach (scandir($path) as $item) {
            if ($item === '.' || $item === '..') continue;
            $full = $path . '/' . $item;
            is_dir($full) ? $this->removeDir($full) : unlink($full);
        }
        rmdir($path);
    }
}
