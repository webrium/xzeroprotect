<?php

declare(strict_types=1);

use PHPUnit\Framework\TestCase;
use Webrium\XZeroProtect\Storage;
use Webrium\XZeroProtect\XZeroProtect;

/**
 * Whitelist boundaries and rate-limit accounting.
 */
class HardeningTest extends TestCase
{
    private string $tmpDir;

    protected function setUp(): void
    {
        $this->tmpDir = sys_get_temp_dir() . '/xzp_hardening_' . uniqid();
        mkdir($this->tmpDir, 0755, true);

        $_SERVER['REMOTE_ADDR']     = '203.0.113.10';
        $_SERVER['REQUEST_METHOD']  = 'GET';
        $_SERVER['HTTP_USER_AGENT'] = 'Mozilla/5.0 Chrome/124.0.0.0';
        $_GET = $_POST = $_COOKIE = [];
    }

    protected function tearDown(): void
    {
        @chmod($this->tmpDir . '/rate', 0755);
        $this->removeDir($this->tmpDir);
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
    // Whitelisted paths must match on a segment boundary
    // =========================================================================

    /**
     * A whitelist entry exempts a request from every firewall check, so a
     * loose prefix match hands an attacker a bypass: whitelisting '/health'
     * used to exempt '/healthcheck-evil/../../etc/passwd' as well.
     *
     * @dataProvider whitelistCases
     */
    public function test_whitelisted_path_matches_on_a_segment_boundary(string $uri, bool $exempt): void
    {
        $reached  = false;
        $firewall = XZeroProtect::init([
            'storage_path' => $this->tmpDir,
            'whitelist'    => ['paths' => ['/health']],
            'auto_ban'     => ['enabled' => false],
        ]);

        $firewall->rules->add('probe', function () use (&$reached) {
            $reached = true;
            return \Webrium\XZeroProtect\RuleResult::pass();
        });

        $_SERVER['REQUEST_URI'] = $uri;
        $firewall->run();

        // A whitelisted request returns before custom rules ever run.
        $this->assertSame($exempt, !$reached, $uri);
    }

    public static function whitelistCases(): array
    {
        return [
            'exact match'        => ['/health', true],
            'child path'         => ['/health/db', true],
            'trailing slash'     => ['/health/', true],
            'with query string'  => ['/health?verbose=1', true],
            'prefix impostor'    => ['/healthcheck-evil', false],
            'unrelated path'     => ['/blog/post', false],
        ];
    }

    // =========================================================================
    // Rate limiting must not lose hits
    // =========================================================================

    public function test_sequential_requests_are_all_counted(): void
    {
        $storage = new Storage($this->tmpDir);

        for ($i = 1; $i <= 10; $i++) {
            $this->assertSame($i, $storage->trackRequest('198.51.100.5', 60));
        }
    }

    public function test_entries_outside_the_window_are_dropped(): void
    {
        $storage = new Storage($this->tmpDir);
        $storage->trackRequest('198.51.100.6', 60);

        // A one-second window makes every earlier hit stale.
        sleep(1);
        $this->assertSame(1, $storage->trackRequest('198.51.100.6', 1));
    }

    /**
     * The counter is a read-modify-write cycle. Locking only the write — as it
     * used to — silently drops hits exactly when requests overlap, which is
     * the only situation a rate limiter exists for.
     */
    public function test_concurrent_requests_are_all_counted(): void
    {
        $script = $this->tmpDir . '/hit.php';
        file_put_contents($script, sprintf(
            '<?php require %s; (new Webrium\XZeroProtect\Storage(%s))->trackRequest("198.51.100.7", 60);',
            var_export(dirname(__DIR__) . '/vendor/autoload.php', true),
            var_export($this->tmpDir, true)
        ));

        $workers = 12;
        $handles = [];

        for ($i = 0; $i < $workers; $i++) {
            $handle = proc_open(
                [PHP_BINARY, $script],
                [1 => ['pipe', 'w'], 2 => ['pipe', 'w']],
                $pipes
            );

            if ($handle === false) {
                $this->markTestSkipped('cannot spawn worker processes here');
            }

            $handles[] = [$handle, $pipes];
        }

        foreach ($handles as [$handle, $pipes]) {
            foreach ($pipes as $pipe) {
                fclose($pipe);
            }
            proc_close($handle);
        }

        $storage = new Storage($this->tmpDir);

        $this->assertSame(
            $workers,
            $storage->getRateCount('198.51.100.7', 60),
            'every concurrent hit must be recorded'
        );
    }

    public function test_unwritable_rate_storage_does_not_break_the_request(): void
    {
        if (function_exists('posix_geteuid') && posix_geteuid() === 0) {
            $this->markTestSkipped('running as root: permission bits are not enforced');
        }

        $storage = new Storage($this->tmpDir);
        chmod($this->tmpDir . '/rate', 0555);

        $this->assertSame(0, $storage->trackRequest('198.51.100.8', 60));
    }
}
