<?php

declare(strict_types=1);

use PHPUnit\Framework\TestCase;
use Webrium\XZeroProtect\RateLimiter;
use Webrium\XZeroProtect\Storage;
use Webrium\XZeroProtect\XZeroProtect;

/**
 * A real page load can fire far more requests than the rate limit allows —
 * a dashboard's async widgets, a flaky connection retrying, a few browser
 * tabs. Every one of those over-limit requests was blocked AND recorded as
 * an auto-ban violation, so a single bursty page load could, by itself,
 * accumulate enough violations to ban the visitor for 24h.
 *
 * A separate defect compounded it: violations never expired. A one-off blip
 * from months ago still counted toward today's ban.
 *
 * These tests pin both fixes: a rate-limit violation is now debounced to at
 * most one per rate-limit window, and violations decay out of a rolling
 * window instead of accumulating forever. Sustained abuse — the thing
 * auto_ban exists to catch — must still trip a ban.
 */
class ViolationFairnessTest extends TestCase
{
    private string  $tmpDir;
    private Storage $storage;

    protected function setUp(): void
    {
        $this->tmpDir  = sys_get_temp_dir() . '/xzp_fairness_' . uniqid();
        mkdir($this->tmpDir, 0755, true);
        $this->storage = new Storage($this->tmpDir);
    }

    protected function tearDown(): void
    {
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

    private function violationFile(string $ip): string
    {
        $files = glob($this->tmpDir . '/violations/*.json') ?: [];
        $this->assertNotEmpty($files, "no violation file exists yet for $ip");

        return $files[0];
    }

    // =========================================================================
    // A single burst must not add up to a ban
    // =========================================================================

    public function test_one_bursty_page_load_records_a_single_violation(): void
    {
        $rateLimiter = new RateLimiter($this->storage, 60, 60);
        $violations  = 0;

        // The exact shape of the bug report: one page load, 75 requests
        // (main route + a burst of async widget/API calls), well within a
        // few seconds.
        for ($i = 1; $i <= 75; $i++) {
            if ($rateLimiter->isExceeded('203.0.113.50')) {
                $violations = $this->storage->incrementViolation('203.0.113.50', 3600, $rateLimiter->getWindow());
            }
        }

        $this->assertSame(
            1,
            $violations,
            'a single burst must not accumulate multiple violations — the default threshold is 10'
        );
    }

    public function test_debounced_violations_still_block_every_over_limit_request(): void
    {
        // Debouncing affects the ban counter only. Blocking itself is
        // RateLimiter::isExceeded(), called independently for every request —
        // unaffected by the cooldown on recording a violation.
        $rateLimiter = new RateLimiter($this->storage, 60, 60);
        $blocked     = 0;

        for ($i = 1; $i <= 75; $i++) {
            if ($rateLimiter->isExceeded('203.0.113.51')) {
                $blocked++;
                $this->storage->incrementViolation('203.0.113.51', 3600, $rateLimiter->getWindow());
            }
        }

        $this->assertSame(15, $blocked, 'every request past the limit of 60 in a 75-request burst must still be blocked');
    }

    public function test_cooldown_of_zero_records_every_call(): void
    {
        // Path/agent/payload violations are each independently suspicious —
        // no cooldown applies to them.
        for ($i = 1; $i <= 5; $i++) {
            $count = $this->storage->incrementViolation('203.0.113.52', 3600, 0);
        }

        $this->assertSame(5, $count);
    }

    public function test_a_new_violation_after_the_cooldown_elapses_is_recorded(): void
    {
        $this->storage->incrementViolation('203.0.113.53', 3600, 5);

        $file = $this->violationFile('203.0.113.53');
        $data = json_decode((string) file_get_contents($file), true);
        $data[0] -= 6; // pretend the cooldown already elapsed
        file_put_contents($file, json_encode($data));

        $count = $this->storage->incrementViolation('203.0.113.53', 3600, 5);
        $this->assertSame(2, $count);
    }

    // =========================================================================
    // Sustained abuse must still trip a ban
    // =========================================================================

    public function test_sustained_flooding_across_many_windows_still_bans(): void
    {
        $rateLimiter = new RateLimiter($this->storage, 60, 5); // short window for a fast test
        $violations  = 0;

        for ($window = 1; $window <= 10; $window++) {
            for ($i = 1; $i <= 61; $i++) {
                if ($rateLimiter->isExceeded('198.51.100.9')) {
                    $violations = $this->storage->incrementViolation('198.51.100.9', 3600, $rateLimiter->getWindow());
                }
            }

            // Advance past the cooldown boundary between windows, the way
            // time actually would between two separate flooding windows.
            $file = $this->violationFile('198.51.100.9');
            $data = json_decode((string) file_get_contents($file), true);
            $data[count($data) - 1] -= ($rateLimiter->getWindow() + 1);
            file_put_contents($file, json_encode($data));
        }

        $this->assertGreaterThanOrEqual(10, $violations, 'ten separate flooding windows must still reach the default threshold');
    }

    // =========================================================================
    // Violations decay instead of accumulating forever
    // =========================================================================

    public function test_old_violation_ages_out_of_the_window(): void
    {
        $this->storage->incrementViolation('203.0.113.54', 3600);

        $file = $this->violationFile('203.0.113.54');
        $data = json_decode((string) file_get_contents($file), true);
        $data[0] = time() - 7200; // two hours old, outside a one-hour window
        file_put_contents($file, json_encode($data));

        $this->assertSame(0, $this->storage->getViolationCount('203.0.113.54', 3600));
    }

    public function test_ninety_day_old_blip_no_longer_counts(): void
    {
        // The exact scenario raised: one accidental blip, long forgotten.
        $this->storage->incrementViolation('203.0.113.55', 3600);

        $file = $this->violationFile('203.0.113.55');
        $data = [strtotime('-90 days')];
        file_put_contents($file, json_encode($data));

        $this->assertSame(0, $this->storage->getViolationCount('203.0.113.55', 3600));
    }

    public function test_recent_violation_within_the_window_still_counts(): void
    {
        $this->storage->incrementViolation('203.0.113.56', 3600, 0);
        $this->storage->incrementViolation('203.0.113.56', 3600, 0);

        $this->assertSame(2, $this->storage->getViolationCount('203.0.113.56', 3600));
    }

    public function test_decay_window_is_configurable(): void
    {
        $this->storage->incrementViolation('203.0.113.57', 60, 0);

        $file = $this->violationFile('203.0.113.57');
        $data = json_decode((string) file_get_contents($file), true);
        $data[0] = time() - 120; // 2 minutes old

        file_put_contents($file, json_encode($data));

        $this->assertSame(0, $this->storage->getViolationCount('203.0.113.57', 60), 'expired under a 60s window');
        $this->assertSame(1, $this->storage->getViolationCount('203.0.113.57', 3600), 'still valid under a 1h window');
    }

    // =========================================================================
    // Pre-existing storage format upgrades safely
    // =========================================================================

    public function test_legacy_violation_file_format_does_not_crash_or_misbehave(): void
    {
        // Create the file at the real path first (naming is Storage's own
        // concern), then overwrite it with the pre-decay-window format.
        $this->storage->incrementViolation('203.0.113.58', 3600, 0);
        file_put_contents(
            $this->violationFile('203.0.113.58'),
            json_encode(['count' => 4, 'first' => time() - 100, 'last' => time() - 10])
        );

        // 'count' (4) is nowhere near a real Unix timestamp, so once the
        // decay-window filter runs it is dropped; only the genuine
        // 'first'/'last' entries — both recent — survive.
        $this->assertSame(2, $this->storage->getViolationCount('203.0.113.58', 3600));
    }

    // =========================================================================
    // Storage-level robustness
    // =========================================================================

    public function test_increment_reindexes_into_a_plain_json_array(): void
    {
        $this->storage->incrementViolation('203.0.113.59', 3600, 0);
        $this->storage->incrementViolation('203.0.113.59', 3600, 0);

        $raw = file_get_contents($this->violationFile('203.0.113.59'));

        // A JSON object ('{"0":...}') would mean the reindex was skipped.
        $this->assertStringStartsWith('[', trim((string) $raw));
    }

    public function test_reset_still_clears_all_recorded_violations(): void
    {
        $this->storage->incrementViolation('203.0.113.60', 3600, 0);
        $this->storage->incrementViolation('203.0.113.60', 3600, 0);
        $this->storage->resetViolations('203.0.113.60');

        $this->assertSame(0, $this->storage->getViolationCount('203.0.113.60', 3600));
    }

    // =========================================================================
    // Integration: the exact config default end-to-end
    // =========================================================================

    public function test_default_config_exposes_a_violation_window(): void
    {
        $firewall = XZeroProtect::init(['storage_path' => $this->tmpDir]);

        // No public getter is needed for this — proving the burst scenario
        // through Storage/RateLimiter directly (above) is the real contract;
        // this just confirms init() does not choke on the new config key.
        $this->assertInstanceOf(XZeroProtect::class, $firewall);
    }
}
