<?php

declare(strict_types=1);

use PHPUnit\Framework\TestCase;
use Webrium\XZeroProtect\CrawlerVerifier;
use Webrium\XZeroProtect\Storage;
use Webrium\XZeroProtect\XZeroProtect;

/**
 * Crawler verifier with the two blocking DNS calls replaced by canned answers,
 * so the suite never touches a real resolver and can count lookups exactly.
 */
class FakeCrawlerVerifier extends CrawlerVerifier
{
    public int $reverseCalls = 0;
    public int $forwardCalls = 0;

    /** Hostname returned by the reverse lookup; null means "no PTR record". */
    public ?string $hostname = 'crawl-66-249-66-1.googlebot.com';

    /** @var array<int,string> IPs the hostname resolves back to. */
    public array $forwardIps = ['66.249.66.1'];

    public function totalCalls(): int
    {
        return $this->reverseCalls + $this->forwardCalls;
    }

    protected function reverseLookup(string $ip): ?string
    {
        $this->reverseCalls++;

        return $this->hostname;
    }

    protected function forwardLookup(string $hostname): array
    {
        $this->forwardCalls++;

        // Mirror the real implementation, which returns normalized IPs.
        return array_map(
            fn(string $ip): string => ($packed = @inet_pton($ip)) === false ? $ip : (inet_ntop($packed) ?: $ip),
            $this->forwardIps
        );
    }
}

class CrawlerCacheTest extends TestCase
{
    private const GOOGLEBOT_UA = 'Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)';
    private const BINGBOT_UA   = 'Mozilla/5.0 (compatible; bingbot/2.0; +http://www.bing.com/bingbot.htm)';
    private const GOOGLEBOT_IP = '66.249.66.1';

    private string  $rulesDir;
    private string  $tmpDir;
    private Storage $storage;

    protected function setUp(): void
    {
        $this->rulesDir = dirname(__DIR__) . '/rules';
        $this->tmpDir   = sys_get_temp_dir() . '/xzp_dnscache_' . uniqid();
        mkdir($this->tmpDir, 0755, true);
        $this->storage = new Storage($this->tmpDir);
    }

    protected function tearDown(): void
    {
        @chmod($this->tmpDir . '/dns', 0755);
        $this->removeDir($this->tmpDir);
    }

    // =========================================================================
    // Helpers
    // =========================================================================

    private function verifier(array $cacheConfig = [], ?Storage $storage = null): FakeCrawlerVerifier
    {
        return new FakeCrawlerVerifier($this->rulesDir, $storage ?? $this->storage, $cacheConfig);
    }

    /** @return array<int,string> */
    private function cacheFiles(): array
    {
        return glob($this->tmpDir . '/dns/*.json') ?: [];
    }

    private function onlyCacheFile(): string
    {
        $files = $this->cacheFiles();
        $this->assertCount(1, $files, 'expected exactly one cache entry');

        return $files[0];
    }

    private function readCacheFile(string $file): array
    {
        return json_decode((string) file_get_contents($file), true);
    }

    private function expireCacheFile(string $file): void
    {
        $data            = $this->readCacheFile($file);
        $data['expires'] = time() - 1;
        file_put_contents($file, json_encode($data));
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
    // Caching behaviour
    // =========================================================================

    public function test_verified_crawler_is_resolved_once_then_cached(): void
    {
        $verifier = $this->verifier();

        $this->assertTrue($verifier->isTrustedCrawler(self::GOOGLEBOT_IP, self::GOOGLEBOT_UA));
        $this->assertSame(1, $verifier->reverseCalls);
        $this->assertSame(1, $verifier->forwardCalls);

        $this->assertTrue($verifier->isTrustedCrawler(self::GOOGLEBOT_IP, self::GOOGLEBOT_UA));
        $this->assertSame(1, $verifier->reverseCalls, 'second call must hit the cache');
        $this->assertSame(1, $verifier->forwardCalls, 'both lookups must be skipped');
    }

    public function test_cached_verdict_survives_a_new_request(): void
    {
        $this->verifier()->isTrustedCrawler(self::GOOGLEBOT_IP, self::GOOGLEBOT_UA);

        // A fresh instance stands in for the next PHP request.
        $next = $this->verifier();

        $this->assertTrue($next->isTrustedCrawler(self::GOOGLEBOT_IP, self::GOOGLEBOT_UA));
        $this->assertSame(0, $next->totalCalls(), 'disk cache must serve the next request');
    }

    public function test_failed_verification_is_cached_too(): void
    {
        $verifier = $this->verifier();
        $verifier->hostname = null;   // no PTR record — spoofed crawler UA

        $this->assertFalse($verifier->isTrustedCrawler('198.51.100.7', self::GOOGLEBOT_UA));
        $this->assertSame(1, $verifier->reverseCalls);

        $next = $this->verifier();
        $next->hostname = null;

        $this->assertFalse($next->isTrustedCrawler('198.51.100.7', self::GOOGLEBOT_UA));
        $this->assertSame(0, $next->totalCalls(), 'spoofed UA floods must not re-resolve');
    }

    public function test_positive_and_negative_verdicts_use_different_ttls(): void
    {
        $verifier = $this->verifier(['ttl' => 86400, 'negative_ttl' => 3600]);
        $verifier->isTrustedCrawler(self::GOOGLEBOT_IP, self::GOOGLEBOT_UA);

        $positive = $this->readCacheFile($this->onlyCacheFile());
        $this->assertTrue($positive['trusted']);
        $this->assertEqualsWithDelta(86400, $positive['expires'] - time(), 5);

        $this->storage->clearDnsCache();

        $failing = $this->verifier(['ttl' => 86400, 'negative_ttl' => 3600]);
        $failing->hostname = null;
        $failing->isTrustedCrawler('198.51.100.7', self::GOOGLEBOT_UA);

        $negative = $this->readCacheFile($this->onlyCacheFile());
        $this->assertFalse($negative['trusted']);
        $this->assertEqualsWithDelta(3600, $negative['expires'] - time(), 5);
    }

    public function test_expired_entry_triggers_a_fresh_lookup(): void
    {
        $this->verifier()->isTrustedCrawler(self::GOOGLEBOT_IP, self::GOOGLEBOT_UA);
        $this->expireCacheFile($this->onlyCacheFile());

        $next = $this->verifier();

        $this->assertTrue($next->isTrustedCrawler(self::GOOGLEBOT_IP, self::GOOGLEBOT_UA));
        $this->assertSame(1, $next->reverseCalls, 'expired entry must be re-resolved');
    }

    public function test_expired_negative_entry_allows_a_crawler_back_in(): void
    {
        // A transient resolver failure must not lock Googlebot out permanently.
        $failing = $this->verifier();
        $failing->hostname = null;
        $this->assertFalse($failing->isTrustedCrawler(self::GOOGLEBOT_IP, self::GOOGLEBOT_UA));

        $this->expireCacheFile($this->onlyCacheFile());

        $recovered = $this->verifier();
        $this->assertTrue($recovered->isTrustedCrawler(self::GOOGLEBOT_IP, self::GOOGLEBOT_UA));
    }

    public function test_expired_entry_is_deleted_on_read(): void
    {
        $this->storage->writeDnsCache('some-key', true, 60);
        $file = $this->onlyCacheFile();
        $this->expireCacheFile($file);

        $this->assertNull($this->storage->readDnsCache('some-key'));
        $this->assertFileDoesNotExist($file);
    }

    // =========================================================================
    // Corrupt / hostile cache state
    // =========================================================================

    /**
     * @dataProvider corruptEntries
     */
    public function test_corrupt_cache_entry_is_treated_as_a_miss(string $contents, string $label): void
    {
        $this->verifier()->isTrustedCrawler(self::GOOGLEBOT_IP, self::GOOGLEBOT_UA);
        file_put_contents($this->onlyCacheFile(), $contents);

        $next = $this->verifier();

        $this->assertTrue($next->isTrustedCrawler(self::GOOGLEBOT_IP, self::GOOGLEBOT_UA), $label);
        $this->assertSame(1, $next->reverseCalls, $label . ': must re-resolve');
    }

    public static function corruptEntries(): array
    {
        return [
            'empty file'          => ['', 'empty'],
            'truncated json'      => ['{"trusted":true,"expi', 'truncated'],
            'not json at all'     => ['<html>502 Bad Gateway</html>', 'garbage'],
            'json but not array'  => ['"just a string"', 'scalar'],
            'missing expires'     => ['{"trusted":true}', 'missing key'],
            'missing trusted'     => ['{"expires":99999999999}', 'missing key'],
            'string trusted'      => ['{"trusted":"yes","expires":99999999999}', 'wrong type'],
            'string expires'      => ['{"trusted":true,"expires":"soon"}', 'wrong type'],
            'null values'         => ['{"trusted":null,"expires":null}', 'null'],
            'nested array'        => ['{"trusted":[1],"expires":[2]}', 'array'],
        ];
    }

    public function test_unwritable_cache_directory_does_not_break_verification(): void
    {
        if (function_exists('posix_geteuid') && posix_geteuid() === 0) {
            $this->markTestSkipped('running as root: permission bits are not enforced');
        }

        chmod($this->tmpDir . '/dns', 0555);

        $verifier = $this->verifier();

        $this->assertTrue($verifier->isTrustedCrawler(self::GOOGLEBOT_IP, self::GOOGLEBOT_UA));
        $this->assertSame([], $this->cacheFiles(), 'nothing should have been written');

        // Degrades to extra lookups on the next request, never to a failure.
        $next = $this->verifier();
        $this->assertTrue($next->isTrustedCrawler(self::GOOGLEBOT_IP, self::GOOGLEBOT_UA));
    }

    public function test_directory_traversal_cannot_escape_the_cache_directory(): void
    {
        $this->storage->writeDnsCache('../../evil', true, 3600);

        $this->assertFileDoesNotExist(dirname($this->tmpDir) . '/evil.json');
        $this->assertCount(1, $this->cacheFiles());
    }

    // =========================================================================
    // Cache configuration
    // =========================================================================

    public function test_cache_can_be_disabled(): void
    {
        $verifier = $this->verifier(['enabled' => false]);

        $verifier->isTrustedCrawler(self::GOOGLEBOT_IP, self::GOOGLEBOT_UA);
        $verifier->isTrustedCrawler(self::GOOGLEBOT_IP, self::GOOGLEBOT_UA);

        $this->assertSame(2, $verifier->reverseCalls, 'every call must resolve when disabled');
        $this->assertSame([], $this->cacheFiles());
        $this->assertFalse($verifier->isCacheEnabled());
    }

    public function test_zero_ttl_keeps_the_verdict_out_of_disk(): void
    {
        $verifier = $this->verifier(['ttl' => 0]);
        $verifier->isTrustedCrawler(self::GOOGLEBOT_IP, self::GOOGLEBOT_UA);

        $this->assertSame([], $this->cacheFiles());
        $this->assertSame(1, $verifier->reverseCalls);

        // The in-memory layer still spares a second lookup within one request.
        $verifier->isTrustedCrawler(self::GOOGLEBOT_IP, self::GOOGLEBOT_UA);
        $this->assertSame(1, $verifier->reverseCalls);
    }

    public function test_negative_ttl_of_zero_only_affects_failures(): void
    {
        $failing = $this->verifier(['negative_ttl' => 0]);
        $failing->hostname = null;
        $failing->isTrustedCrawler('198.51.100.7', self::GOOGLEBOT_UA);
        $this->assertSame([], $this->cacheFiles());

        $ok = $this->verifier(['negative_ttl' => 0]);
        $ok->isTrustedCrawler(self::GOOGLEBOT_IP, self::GOOGLEBOT_UA);
        $this->assertCount(1, $this->cacheFiles());
    }

    public function test_negative_ttl_config_is_clamped_at_zero(): void
    {
        $verifier = $this->verifier(['ttl' => -1, 'negative_ttl' => -100]);
        $verifier->isTrustedCrawler(self::GOOGLEBOT_IP, self::GOOGLEBOT_UA);

        $this->assertSame([], $this->cacheFiles());
    }

    public function test_without_storage_the_cache_is_memory_only(): void
    {
        $verifier = new FakeCrawlerVerifier($this->rulesDir);

        $verifier->isTrustedCrawler(self::GOOGLEBOT_IP, self::GOOGLEBOT_UA);
        $verifier->isTrustedCrawler(self::GOOGLEBOT_IP, self::GOOGLEBOT_UA);

        $this->assertSame(1, $verifier->reverseCalls, 'in-memory layer still applies');
        $this->assertFalse($verifier->isCachePersistent());
        $this->assertTrue($verifier->isCacheEnabled());
    }

    public function test_constructor_remains_backward_compatible(): void
    {
        $verifier = new CrawlerVerifier($this->rulesDir);

        $this->assertFalse($verifier->isCachePersistent());
        $this->assertSame('Googlebot', $verifier->getCrawlerName(self::GOOGLEBOT_UA));
    }

    // =========================================================================
    // Cache keying
    // =========================================================================

    public function test_different_crawlers_on_one_ip_are_cached_separately(): void
    {
        $verifier = $this->verifier();
        $verifier->isTrustedCrawler(self::GOOGLEBOT_IP, self::GOOGLEBOT_UA);

        // Same IP, different expected suffix — must not reuse the Google verdict.
        $verifier->isTrustedCrawler(self::GOOGLEBOT_IP, self::BINGBOT_UA);

        $this->assertSame(2, $verifier->reverseCalls);
        $this->assertCount(2, $this->cacheFiles());
    }

    public function test_ipv6_notation_variants_share_one_entry(): void
    {
        $verifier = $this->verifier();
        $verifier->hostname   = 'crawl-2001-db8.googlebot.com';
        $verifier->forwardIps = ['2001:db8::1'];

        $this->assertTrue($verifier->isTrustedCrawler('2001:db8::1', self::GOOGLEBOT_UA));
        $this->assertTrue($verifier->isTrustedCrawler('2001:0db8:0000:0000:0000:0000:0000:0001', self::GOOGLEBOT_UA));

        $this->assertSame(1, $verifier->reverseCalls, 'both notations are the same address');
        $this->assertCount(1, $this->cacheFiles());
    }

    public function test_cache_filename_is_filesystem_safe(): void
    {
        $this->verifier()->isTrustedCrawler(self::GOOGLEBOT_IP, self::GOOGLEBOT_UA);

        $this->assertMatchesRegularExpression('/^[a-f0-9]{40}\.json$/', basename($this->onlyCacheFile()));
    }

    // =========================================================================
    // Cache management
    // =========================================================================

    public function test_clear_cache_forces_a_fresh_lookup(): void
    {
        $verifier = $this->verifier();
        $verifier->isTrustedCrawler(self::GOOGLEBOT_IP, self::GOOGLEBOT_UA);

        $verifier->clearCache();

        $this->assertSame([], $this->cacheFiles());
        $verifier->isTrustedCrawler(self::GOOGLEBOT_IP, self::GOOGLEBOT_UA);
        $this->assertSame(2, $verifier->reverseCalls);
    }

    public function test_cleanup_removes_expired_entries_and_keeps_fresh_ones(): void
    {
        $verifier = $this->verifier();
        $verifier->isTrustedCrawler(self::GOOGLEBOT_IP, self::GOOGLEBOT_UA);
        $this->expireCacheFile($this->onlyCacheFile());

        $verifier->isTrustedCrawler(self::GOOGLEBOT_IP, self::BINGBOT_UA);
        $this->assertCount(2, $this->cacheFiles());

        $verifier->cleanupCache();

        $this->assertCount(1, $this->cacheFiles(), 'only the expired entry should go');
    }

    public function test_cleanup_removes_unreadable_entries(): void
    {
        $this->verifier()->isTrustedCrawler(self::GOOGLEBOT_IP, self::GOOGLEBOT_UA);
        file_put_contents($this->onlyCacheFile(), 'not json');

        $this->storage->cleanupDnsCache();

        $this->assertSame([], $this->cacheFiles());
    }

    public function test_cleanup_on_empty_cache_is_harmless(): void
    {
        $this->storage->cleanupDnsCache();
        $this->storage->clearDnsCache();

        $this->assertSame([], $this->cacheFiles());
    }

    // =========================================================================
    // Paths that must never reach DNS
    // =========================================================================

    public function test_crawler_without_rdns_verification_never_resolves(): void
    {
        $verifier = $this->verifier();

        $this->assertTrue($verifier->isTrustedCrawler('1.2.3.4', 'Twitterbot/1.0'));
        $this->assertSame(0, $verifier->totalCalls());
        $this->assertSame([], $this->cacheFiles());
    }

    public function test_ordinary_browser_never_resolves(): void
    {
        $verifier = $this->verifier();

        $this->assertFalse($verifier->isTrustedCrawler('1.2.3.4', 'Mozilla/5.0 Chrome/124.0.0.0'));
        $this->assertSame(0, $verifier->totalCalls());
    }

    public function test_empty_user_agent_never_resolves(): void
    {
        $verifier = $this->verifier();

        $this->assertFalse($verifier->isTrustedCrawler('1.2.3.4', ''));
        $this->assertFalse($verifier->isTrustedCrawler('1.2.3.4', '   '));
        $this->assertSame(0, $verifier->totalCalls());
    }

    // =========================================================================
    // Verification correctness is unchanged by caching
    // =========================================================================

    public function test_wrong_rdns_suffix_is_not_trusted(): void
    {
        $verifier = $this->verifier();
        $verifier->hostname = 'crawler.evil-example.com';

        $this->assertFalse($verifier->isTrustedCrawler(self::GOOGLEBOT_IP, self::GOOGLEBOT_UA));
    }

    public function test_forward_lookup_mismatch_is_not_trusted(): void
    {
        $verifier = $this->verifier();
        $verifier->forwardIps = ['203.0.113.99'];

        $this->assertFalse($verifier->isTrustedCrawler(self::GOOGLEBOT_IP, self::GOOGLEBOT_UA));
    }

    public function test_forward_lookup_returning_nothing_is_not_trusted(): void
    {
        $verifier = $this->verifier();
        $verifier->forwardIps = [];

        $this->assertFalse($verifier->isTrustedCrawler(self::GOOGLEBOT_IP, self::GOOGLEBOT_UA));
    }

    public function test_suffix_match_is_case_insensitive(): void
    {
        $verifier = $this->verifier();
        $verifier->hostname = 'CRAWL-66-249-66-1.GOOGLEBOT.COM';

        $this->assertTrue($verifier->isTrustedCrawler(self::GOOGLEBOT_IP, self::GOOGLEBOT_UA));
    }

    // =========================================================================
    // Storage-level contract
    // =========================================================================

    public function test_storage_read_returns_null_for_unknown_key(): void
    {
        $this->assertNull($this->storage->readDnsCache('never-written'));
    }

    public function test_storage_round_trips_both_verdicts(): void
    {
        $this->storage->writeDnsCache('yes', true, 60);
        $this->storage->writeDnsCache('no', false, 60);

        $this->assertTrue($this->storage->readDnsCache('yes'));
        $this->assertFalse($this->storage->readDnsCache('no'));
    }

    public function test_storage_delete_removes_an_entry(): void
    {
        $this->storage->writeDnsCache('key', true, 60);
        $this->storage->deleteDnsCache('key');

        $this->assertNull($this->storage->readDnsCache('key'));
    }

    public function test_storage_creates_the_dns_directory(): void
    {
        $this->assertDirectoryExists($this->tmpDir . '/dns');
    }

    // =========================================================================
    // Integration
    // =========================================================================

    public function test_firewall_passes_storage_into_the_verifier(): void
    {
        $firewall = XZeroProtect::init(['storage_path' => $this->tmpDir]);

        $this->assertTrue($firewall->crawlers->isCachePersistent());
    }

    public function test_firewall_honours_crawler_cache_config(): void
    {
        $firewall = XZeroProtect::init([
            'storage_path'  => $this->tmpDir,
            'crawler_cache' => ['enabled' => false],
        ]);

        $this->assertFalse($firewall->crawlers->isCacheEnabled());
        $this->assertFalse($firewall->crawlers->isCachePersistent());
    }
}
