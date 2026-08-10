<?php

declare(strict_types=1);

use PHPUnit\Framework\TestCase;
use Webrium\XZeroProtect\VisitInfo;
use Webrium\XZeroProtect\XZeroProtect;

/**
 * Firewall with the two SAPI-bound seams replaced, so the deferred tracking
 * path can be driven without ending the process or sending real headers.
 */
class TestableXZeroProtect extends XZeroProtect
{
    /** @var array<int,\Closure> Callbacks that register_shutdown_function would hold */
    public array $deferred = [];

    /** Status the finished response reports. */
    public int $status = 200;

    /** Runs everything a real shutdown would run. */
    public function runShutdown(): void
    {
        $callbacks       = $this->deferred;
        $this->deferred  = [];

        foreach ($callbacks as $callback) {
            $callback();
        }
    }

    protected function deferToShutdown(\Closure $callback): void
    {
        $this->deferred[] = $callback;
    }

    protected function responseStatus(): int
    {
        return $this->status;
    }
}

class DeferredTrackingTest extends TestCase
{
    private string $tmpDir;

    /** @var array<int,string> */
    private array $recorded = [];

    protected function setUp(): void
    {
        $this->tmpDir   = sys_get_temp_dir() . '/xzp_deferred_' . uniqid();
        $this->recorded = [];
        mkdir($this->tmpDir, 0755, true);

        $_SERVER['REMOTE_ADDR']     = '203.0.113.10';
        $_SERVER['REQUEST_METHOD']  = 'GET';
        $_SERVER['REQUEST_URI']     = '/blog/how-to-build-a-cms';
        $_SERVER['HTTP_USER_AGENT'] = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/124.0.0.0 Safari/537.36';
        $_GET = $_POST = $_COOKIE = [];

        foreach (['HTTP_SEC_FETCH_DEST', 'HTTP_X_REQUESTED_WITH', 'HTTP_SEC_PURPOSE'] as $header) {
            unset($_SERVER[$header]);
        }
    }

    protected function tearDown(): void
    {
        $this->removeDir($this->tmpDir);
    }

    // =========================================================================
    // Helpers
    // =========================================================================

    private function firewall(array $tracking = []): TestableXZeroProtect
    {
        /** @var TestableXZeroProtect $firewall */
        $firewall = TestableXZeroProtect::init([
            'storage_path' => $this->tmpDir,
            'tracking'     => $tracking,
        ]);

        $firewall->enableTracking(function (VisitInfo $visit) {
            $this->recorded[] = $visit->path;
        });

        return $firewall;
    }

    private function shutdownFirewall(array $tracking = []): TestableXZeroProtect
    {
        return $this->firewall(array_merge(['when' => 'shutdown'], $tracking));
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
    // Mode selection
    // =========================================================================

    public function test_immediate_is_the_default(): void
    {
        $this->assertSame('immediate', $this->firewall()->getTrackingWhen());
    }

    public function test_immediate_mode_records_during_run(): void
    {
        $firewall = $this->firewall();
        $firewall->run();

        $this->assertSame(['/blog/how-to-build-a-cms'], $this->recorded);
        $this->assertSame([], $firewall->deferred, 'nothing should be deferred');
    }

    public function test_immediate_mode_ignores_the_response_status(): void
    {
        // Nothing has been routed yet during run(), so only_status cannot
        // apply here — it must not silently drop the visit either.
        $firewall = $this->firewall(['only_status' => [200]]);
        $firewall->status = 404;
        $firewall->run();

        $this->assertSame(['/blog/how-to-build-a-cms'], $this->recorded);
    }

    public function test_shutdown_mode_defers_the_callback(): void
    {
        $firewall = $this->shutdownFirewall();
        $firewall->run();

        $this->assertSame([], $this->recorded, 'must not fire during run()');
        $this->assertCount(1, $firewall->deferred);

        $firewall->runShutdown();

        $this->assertSame(['/blog/how-to-build-a-cms'], $this->recorded);
    }

    public function test_unknown_mode_falls_back_to_immediate(): void
    {
        $firewall = $this->firewall(['when' => 'whenever']);
        $firewall->run();

        $this->assertSame('immediate', $firewall->getTrackingWhen());
        $this->assertSame(['/blog/how-to-build-a-cms'], $this->recorded);
    }

    public function test_mode_value_is_case_and_space_insensitive(): void
    {
        $this->assertSame('shutdown', $this->firewall(['when' => '  SHUTDOWN '])->getTrackingWhen());
    }

    public function test_mode_can_be_changed_at_runtime(): void
    {
        $firewall = $this->firewall();
        $firewall->setTrackingWhen('shutdown');
        $firewall->run();

        $this->assertSame([], $this->recorded);
        $firewall->runShutdown();
        $this->assertSame(['/blog/how-to-build-a-cms'], $this->recorded);
    }

    // =========================================================================
    // Status filtering
    // =========================================================================

    public function test_successful_page_is_recorded(): void
    {
        $firewall = $this->shutdownFirewall();
        $firewall->status = 200;
        $firewall->run();
        $firewall->runShutdown();

        $this->assertSame(['/blog/how-to-build-a-cms'], $this->recorded);
    }

    /**
     * @dataProvider uncountedStatuses
     */
    public function test_non_page_response_is_not_recorded(int $status): void
    {
        $firewall = $this->shutdownFirewall();
        $firewall->status = $status;
        $firewall->run();
        $firewall->runShutdown();

        $this->assertSame([], $this->recorded, 'status ' . $status . ' is not a page view');
    }

    public static function uncountedStatuses(): array
    {
        return [
            'not found'      => [404],
            'gone'           => [410],
            'permanent move' => [301],
            'temporary move' => [302],
            'server error'   => [500],
            'unavailable'    => [503],
            'forbidden'      => [403],
            'unauthorized'   => [401],
        ];
    }

    public function test_tracked_statuses_are_configurable(): void
    {
        $firewall = $this->shutdownFirewall(['only_status' => [200, 404]]);
        $firewall->status = 404;
        $firewall->run();
        $firewall->runShutdown();

        $this->assertSame(['/blog/how-to-build-a-cms'], $this->recorded);
    }

    public function test_empty_status_list_records_any_response(): void
    {
        $firewall = $this->shutdownFirewall(['only_status' => []]);
        $firewall->status = 500;
        $firewall->run();
        $firewall->runShutdown();

        $this->assertSame(['/blog/how-to-build-a-cms'], $this->recorded);
    }

    public function test_statuses_can_be_changed_at_runtime(): void
    {
        $firewall = $this->shutdownFirewall();
        $firewall->setTrackedStatuses([404]);
        $firewall->status = 404;
        $firewall->run();
        $firewall->runShutdown();

        $this->assertSame(['/blog/how-to-build-a-cms'], $this->recorded);
    }

    public function test_status_values_are_normalized_to_int(): void
    {
        $firewall = $this->shutdownFirewall(['only_status' => ['200', 200, '404']]);

        $this->assertSame([200, 404], $firewall->getTrackedStatuses());
    }

    public function test_string_status_config_still_matches(): void
    {
        // in_array() is strict, so a config written as ['200'] must have been
        // cast at construction or the visit would be silently dropped.
        $firewall = $this->shutdownFirewall(['only_status' => ['200']]);
        $firewall->status = 200;
        $firewall->run();
        $firewall->runShutdown();

        $this->assertSame(['/blog/how-to-build-a-cms'], $this->recorded);
    }

    // =========================================================================
    // Interaction with the visit filter
    // =========================================================================

    public function test_filtered_request_is_never_deferred(): void
    {
        $firewall = $this->shutdownFirewall();
        $_SERVER['REQUEST_URI'] = '/assets/vazir.woff2';
        $firewall->run();

        $this->assertSame([], $firewall->deferred, 'no shutdown slot for an asset');

        $firewall->runShutdown();
        $this->assertSame([], $this->recorded);
    }

    public function test_prefetch_is_never_deferred(): void
    {
        $firewall = $this->shutdownFirewall();
        $_SERVER['HTTP_SEC_PURPOSE'] = 'prefetch';
        $firewall->run();

        $this->assertSame([], $firewall->deferred);
        unset($_SERVER['HTTP_SEC_PURPOSE']);
    }

    public function test_disabled_tracking_defers_nothing(): void
    {
        $firewall = $this->shutdownFirewall();
        $firewall->disableTracking();
        $firewall->run();

        $this->assertSame([], $firewall->deferred);
    }

    // =========================================================================
    // Robustness
    // =========================================================================

    public function test_visit_timestamp_is_the_arrival_time_not_the_flush_time(): void
    {
        $seen = null;
        $firewall = TestableXZeroProtect::init([
            'storage_path' => $this->tmpDir,
            'tracking'     => ['when' => 'shutdown'],
        ]);
        $firewall->enableTracking(function (VisitInfo $visit) use (&$seen) {
            $seen = $visit->timestamp;
        });

        $before = time();
        $firewall->run();
        $firewall->runShutdown();

        $this->assertNotNull($seen);
        $this->assertLessThanOrEqual(time(), $seen);
        $this->assertGreaterThanOrEqual($before, $seen);
    }

    public function test_throwing_callback_does_not_break_shutdown(): void
    {
        $firewall = TestableXZeroProtect::init([
            'storage_path' => $this->tmpDir,
            'tracking'     => ['when' => 'shutdown'],
        ]);
        $firewall->enableTracking(function () {
            throw new \RuntimeException('database is down');
        });

        $firewall->run();
        $firewall->runShutdown();

        $this->assertTrue(true, 'shutdown completed without propagating the exception');
    }

    // =========================================================================
    // Config merging — a list in config must replace the default, not overlay it
    // =========================================================================

    public function test_empty_list_in_config_clears_the_default(): void
    {
        $firewall = $this->firewall(['only_status' => [], 'methods' => []]);

        $this->assertSame([], $firewall->getTrackedStatuses());
        $this->assertSame([], $firewall->visits->getMethods());
    }

    public function test_shorter_list_in_config_does_not_leave_a_tail_behind(): void
    {
        $firewall = $this->firewall(['track_dest' => ['iframe']]);

        $this->assertSame(['iframe'], $firewall->visits->getTrackedDest());
    }

    public function test_partial_section_override_keeps_sibling_values(): void
    {
        $firewall = $this->firewall(['methods' => ['GET', 'POST']]);

        // 'methods' replaced, but the rest of the tracking section is intact.
        $this->assertSame(['GET', 'POST'], $firewall->visits->getMethods());
        $this->assertSame(['document'], $firewall->visits->getTrackedDest());
        $this->assertTrue($firewall->visits->isEnabled());
    }

    public function test_one_request_defers_exactly_one_visit(): void
    {
        $firewall = $this->shutdownFirewall();
        $firewall->run();
        $firewall->runShutdown();
        $firewall->runShutdown();

        $this->assertCount(1, $this->recorded, 'a flushed visit must not fire twice');
    }
}
