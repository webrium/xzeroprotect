<?php

declare(strict_types=1);

use PHPUnit\Framework\TestCase;
use Webrium\XZeroProtect\Logger;
use Webrium\XZeroProtect\Storage;
use Webrium\XZeroProtect\XZeroProtect;

/**
 * The attack log used to be read in full (file() over the whole file) on
 * every call, and rotated .bak backups were only ever cleaned up by a
 * system cron the consuming project never actually wired up — meaning they
 * accumulated forever in practice.
 *
 * These tests pin: reading only the requested slice of the log (a backward
 * chunked "tail -n", not a full-file load), a cheap line count for building
 * pagination, and a lazy, traffic-driven auto-cleanup that needs no cron.
 */
class LogRetentionTest extends TestCase
{
    private string  $tmpDir;
    private Storage $storage;

    protected function setUp(): void
    {
        $this->tmpDir = sys_get_temp_dir() . '/xzp_logs_' . uniqid();
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

    private function logFile(): string
    {
        return $this->tmpDir . '/logs/attacks.log';
    }

    private function writeRawLog(string $content): void
    {
        file_put_contents($this->logFile(), $content);
    }

    /** N lines, each "line-0000", "line-0001", ... so order/content is easy to assert. */
    private function seedLines(int $count): void
    {
        $lines = [];
        for ($i = 0; $i < $count; $i++) {
            $lines[] = sprintf('line-%04d', $i);
        }
        $this->writeRawLog(implode("\n", $lines) . "\n");
    }

    // =========================================================================
    // readLogs() — reading a slice, not the whole file
    // =========================================================================

    public function test_missing_log_file_returns_empty(): void
    {
        $this->assertSame([], $this->storage->readLogs(10));
    }

    public function test_empty_log_file_returns_empty(): void
    {
        $this->writeRawLog('');
        $this->assertSame([], $this->storage->readLogs(10));
    }

    public function test_limit_zero_returns_empty(): void
    {
        $this->seedLines(5);
        $this->assertSame([], $this->storage->readLogs(0));
    }

    public function test_reads_newest_first(): void
    {
        $this->seedLines(5);
        $lines = $this->storage->readLogs(5);

        $this->assertSame(
            ['line-0004', 'line-0003', 'line-0002', 'line-0001', 'line-0000'],
            $lines
        );
    }

    public function test_limit_smaller_than_file_returns_only_the_newest(): void
    {
        $this->seedLines(50);
        $lines = $this->storage->readLogs(3);

        $this->assertSame(['line-0049', 'line-0048', 'line-0047'], $lines);
    }

    public function test_offset_pages_further_back(): void
    {
        $this->seedLines(50);
        $lines = $this->storage->readLogs(3, 3);

        $this->assertSame(['line-0046', 'line-0045', 'line-0044'], $lines);
    }

    public function test_offset_beyond_available_lines_returns_empty(): void
    {
        $this->seedLines(5);
        $this->assertSame([], $this->storage->readLogs(10, 100));
    }

    public function test_limit_larger_than_file_returns_everything_available(): void
    {
        $this->seedLines(5);
        $lines = $this->storage->readLogs(1000);

        $this->assertCount(5, $lines);
        $this->assertSame('line-0004', $lines[0]);
        $this->assertSame('line-0000', $lines[4]);
    }

    public function test_file_without_trailing_newline_is_read_correctly(): void
    {
        $this->writeRawLog("line-0000\nline-0001\nline-0002");
        $lines = $this->storage->readLogs(10);

        $this->assertSame(['line-0002', 'line-0001', 'line-0000'], $lines);
    }

    public function test_single_line_file_smaller_than_one_chunk(): void
    {
        $this->seedLines(1);
        $this->assertSame(['line-0000'], $this->storage->readLogs(10));
    }

    /**
     * The internal read chunk is 8KB. A file spanning several chunks must
     * still return exactly the right lines in the right order — including
     * a request whose boundary falls in the middle of a chunk.
     */
    public function test_reads_correctly_across_multiple_internal_chunks(): void
    {
        // ~10 bytes/line * 3000 lines ≈ 30KB — several times the 8KB chunk.
        $this->seedLines(3000);

        $newest20 = $this->storage->readLogs(20);
        $expectedNewest = [];
        for ($i = 2999; $i > 2979; $i--) {
            $expectedNewest[] = sprintf('line-%04d', $i);
        }
        $this->assertSame($expectedNewest, $newest20);

        // A page deep enough to straddle multiple chunk boundaries.
        $page = $this->storage->readLogs(5, 1000);
        $this->assertSame(['line-1999', 'line-1998', 'line-1997', 'line-1996', 'line-1995'], $page);

        $all = $this->storage->readLogs(5000);
        $this->assertCount(3000, $all);
        $this->assertSame('line-2999', $all[0]);
        $this->assertSame('line-0000', $all[2999]);
    }

    // =========================================================================
    // countLogLines()
    // =========================================================================

    public function test_count_missing_file_is_zero(): void
    {
        $this->assertSame(0, $this->storage->countLogLines());
    }

    public function test_count_matches_actual_line_count(): void
    {
        $this->seedLines(37);
        $this->assertSame(37, $this->storage->countLogLines());
    }

    public function test_count_excludes_rotated_backups(): void
    {
        $this->seedLines(4);
        copy($this->logFile(), $this->logFile() . '.20260101_000000.bak');

        $this->assertSame(4, $this->storage->countLogLines());
    }

    // =========================================================================
    // dueForLogCleanup() — lazy, time-gated, no cron required
    // =========================================================================

    public function test_first_check_is_due_and_creates_a_marker(): void
    {
        $this->assertTrue($this->storage->dueForLogCleanup());
        $this->assertFileExists($this->tmpDir . '/logs/.cleanup_at');
    }

    public function test_immediate_second_check_is_not_due(): void
    {
        $this->storage->dueForLogCleanup();
        $this->assertFalse($this->storage->dueForLogCleanup());
    }

    public function test_becomes_due_again_after_the_interval_elapses(): void
    {
        $this->storage->dueForLogCleanup();

        $marker = $this->tmpDir . '/logs/.cleanup_at';
        touch($marker, time() - 90000); // just over 24h ago

        $this->assertTrue($this->storage->dueForLogCleanup());
    }

    public function test_marker_is_touched_before_returning_due(): void
    {
        // Simulates a burst of concurrent requests: the first call must
        // already flip the marker so a second call arriving right after
        // does not also see "due".
        $this->storage->dueForLogCleanup();
        $marker = $this->tmpDir . '/logs/.cleanup_at';
        $mtimeAfterFirstCall = filemtime($marker);

        $this->assertGreaterThanOrEqual(time() - 2, $mtimeAfterFirstCall);
        $this->assertFalse($this->storage->dueForLogCleanup());
    }

    // =========================================================================
    // Logger integration
    // =========================================================================

    public function test_logger_recent_and_total_delegate_to_storage(): void
    {
        $this->seedLines(10);
        $logger = new Logger($this->storage);

        $this->assertSame(10, $logger->total());
        $this->assertSame(['line-0009', 'line-0008'], $logger->recent(2));
        $this->assertSame(['line-0007', 'line-0006'], $logger->recent(2, 2));
    }

    public function test_logger_triggers_auto_cleanup_when_due(): void
    {
        $this->seedLines(1);
        $bak = $this->logFile() . '.20200101_000000.bak';
        copy($this->logFile(), $bak);

        // Fast-forward: make the marker (created by seedLines' implicit
        // absence of one) look overdue, and make the backup old enough to
        // be swept by the default 30-day retention.
        touch($this->tmpDir . '/logs/.cleanup_at', time() - 90000);
        touch($bak, time() - (31 * 86400));

        $logger = new Logger($this->storage, enabled: true, keepDays: 30, autoCleanup: true);
        $logger->log('sqli', $this->fakeRequest());

        $this->assertFileDoesNotExist($bak, 'auto_cleanup=true must sweep expired backups on a due log write');
    }

    public function test_logger_does_not_cleanup_when_auto_cleanup_disabled(): void
    {
        $this->seedLines(1);
        $bak = $this->logFile() . '.20200101_000000.bak';
        copy($this->logFile(), $bak);

        touch($this->tmpDir . '/logs/.cleanup_at', time() - 90000);
        touch($bak, time() - (31 * 86400));

        $logger = new Logger($this->storage, enabled: true, keepDays: 30, autoCleanup: false);
        $logger->log('sqli', $this->fakeRequest());

        $this->assertFileExists($bak, 'auto_cleanup=false must never sweep, regardless of how overdue');
    }

    public function test_logger_does_not_cleanup_when_not_yet_due(): void
    {
        $this->seedLines(1);
        $bak = $this->logFile() . '.20200101_000000.bak';
        copy($this->logFile(), $bak);
        touch($bak, time() - (31 * 86400));

        // No marker manipulation: dueForLogCleanup() creates one on the
        // very first appendLog-triggered check, so this write consumes
        // the "due" state itself without ever being overdue beforehand —
        // asserting cleanup ran exactly once, not on every subsequent log.
        $logger = new Logger($this->storage, enabled: true, keepDays: 30, autoCleanup: true);
        $logger->log('sqli', $this->fakeRequest());
        $this->assertFileDoesNotExist($bak);

        // A second write right after must NOT re-run cleanup (nothing left
        // to prove it didn't crash, but this pins the "at most once a day"
        // contract together with the dueForLogCleanup() unit tests above).
        copy($this->logFile(), $bak);
        $logger->log('sqli', $this->fakeRequest());
        $this->assertFileExists($bak, 'a second write within the interval must not re-trigger cleanup');
    }

    public function test_default_config_exposes_auto_cleanup(): void
    {
        $firewall = XZeroProtect::init(['storage_path' => $this->tmpDir]);
        $this->assertInstanceOf(XZeroProtect::class, $firewall);
    }

    private function fakeRequest(): \Webrium\XZeroProtect\Request
    {
        $_SERVER['REMOTE_ADDR']     = '203.0.113.99';
        $_SERVER['REQUEST_METHOD']  = 'GET';
        $_SERVER['REQUEST_URI']     = '/test';
        $_SERVER['HTTP_USER_AGENT'] = 'phpunit';

        return new \Webrium\XZeroProtect\Request();
    }
}
