<?php

declare(strict_types=1);

namespace Webrium\XZeroProtect;

/**
 * Handles all file-based persistence: banned IPs, rate-limit counters, violation counts.
 */
class Storage
{
    private string $basePath;

    // Sub-directory names
    private const DIR_BANS        = 'bans';
    private const DIR_RATE        = 'rate';
    private const DIR_VIOLATIONS  = 'violations';
    private const DIR_LOGS        = 'logs';
    private const DIR_DNS         = 'dns';

    public function __construct(string $basePath)
    {
        $this->basePath = rtrim($basePath, '/\\');
        $this->ensureDirectories();
    }

    // -------------------------------------------------------------------------
    // Ban management
    // -------------------------------------------------------------------------

    public function isBanned(string $ip): bool
    {
        $data = $this->readBan($ip);
        if ($data === null) {
            return false;
        }

        // Permanent ban
        if ($data['expires'] === 0) {
            return true;
        }

        // Expired?
        if (time() > $data['expires']) {
            $this->deleteBan($ip);
            return false;
        }

        return true;
    }

    public function ban(string $ip, string $reason = '', int $duration = 86400): void
    {
        $expires = ($duration === 0) ? 0 : time() + $duration;

        $data = [
            'ip'        => $ip,
            'reason'    => $reason,
            'banned_at' => time(),
            'expires'   => $expires,
            'bans_count'=> ($this->readBan($ip)['bans_count'] ?? 0) + 1,
        ];

        $this->writeBan($ip, $data);
    }

    public function unban(string $ip): void
    {
        $this->deleteBan($ip);
    }

    public function getBanInfo(string $ip): ?array
    {
        return $this->readBan($ip);
    }

    /**
     * Returns all currently active bans as [ip => data].
     */
    public function getAllBans(): array
    {
        $dir   = $this->dir(self::DIR_BANS);
        $bans  = [];

        foreach (glob($dir . '/*.json') as $file) {
            $data = $this->readJson($file);
            if ($data === null) {
                continue;
            }

            // Skip expired
            if ($data['expires'] !== 0 && time() > $data['expires']) {
                @unlink($file);
                continue;
            }

            $bans[$data['ip']] = $data;
        }

        return $bans;
    }

    public function getBanCount(string $ip): int
    {
        return $this->readBan($ip)['bans_count'] ?? 0;
    }

    // -------------------------------------------------------------------------
    // Violation tracking
    // -------------------------------------------------------------------------

    /**
     * Records a violation and returns the count within the rolling
     * $decayWindow. Stored as a timestamp list, exactly like the rate
     * limiter, so an old, unrelated blip ages out instead of counting
     * against a client forever.
     *
     * $cooldown debounces repeat calls: a burst of many over-limit requests
     * inside one legitimate page load must not, by itself, add up to an
     * auto-ban. Pass 0 (the default) to record every call — appropriate for
     * violation types that are each independently suspicious, such as a
     * blocked path or a payload match. A caller that can fire many times for
     * a single real event (rate-limit overflow during one burst) should pass
     * a cooldown so only the first call in that span is recorded.
     *
     * Read, decay, and write happen under one exclusive lock — the same
     * lost-update risk that applied to the rate counter applies here.
     */
    public function incrementViolation(string $ip, int $decayWindow = 3600, int $cooldown = 0): int
    {
        $handle = @fopen($this->violationFile($ip), 'c+');

        if ($handle === false) {
            return 0; // unwritable storage must not break the request
        }

        try {
            flock($handle, LOCK_EX);

            $timestamps = $this->decayedTimestamps($handle, $decayWindow);
            $now        = time();
            $last       = $timestamps === [] ? null : $timestamps[count($timestamps) - 1];

            if ($cooldown <= 0 || $last === null || ($now - $last) >= $cooldown) {
                $timestamps[] = $now;
            }

            $this->writeTimestamps($handle, $timestamps);

            return count($timestamps);
        } finally {
            flock($handle, LOCK_UN);
            fclose($handle);
        }
    }

    /**
     * Current violation count within the rolling $decayWindow. Read-only —
     * does not prune the stored list, matching getRateCount()'s behavior.
     */
    public function getViolationCount(string $ip, int $decayWindow = 3600): int
    {
        $file = $this->violationFile($ip);
        $now  = time();
        $data = $this->readJson($file);

        // Self-heals a pre-decay-window violation file (an object with
        // count/first/last keys) into the new format: 'count' is far smaller
        // than any real timestamp, so it ages out on the next write and only
        // the genuine 'first'/'last' timestamps are ever counted meanwhile.
        $timestamps = is_array($data) ? array_values(array_filter($data, 'is_int')) : [];

        return count(array_filter($timestamps, fn($t) => ($now - $t) < $decayWindow));
    }

    public function resetViolations(string $ip): void
    {
        @unlink($this->violationFile($ip));
    }

    // -------------------------------------------------------------------------
    // Rate limiting
    // -------------------------------------------------------------------------

    /**
     * Increments the request counter for $ip within a sliding window and
     * returns the count within that window.
     *
     * Read and write happen under one exclusive lock. Locking only the write,
     * as this used to, loses hits whenever two requests from the same IP
     * overlap — which is exactly when the counter matters.
     */
    public function trackRequest(string $ip, int $windowSeconds): int
    {
        $handle = @fopen($this->rateFile($ip), 'c+');

        if ($handle === false) {
            return 0; // unwritable storage must not break the request
        }

        try {
            flock($handle, LOCK_EX);

            $contents = stream_get_contents($handle);
            $data     = is_string($contents) ? json_decode($contents, true) : null;
            $now      = time();

            $data = is_array($data)
                ? array_filter($data, fn($t) => is_int($t) && ($now - $t) < $windowSeconds)
                : [];

            $data[] = $now;
            $data   = array_values($data);

            rewind($handle);
            ftruncate($handle, 0);
            fwrite($handle, json_encode($data));
            fflush($handle);

            return count($data);
        } finally {
            flock($handle, LOCK_UN);
            fclose($handle);
        }
    }

    public function getRateCount(string $ip, int $windowSeconds): int
    {
        $file = $this->rateFile($ip);
        $now  = time();
        $data = $this->readJson($file) ?? [];
        return count(array_filter($data, fn($t) => ($now - $t) < $windowSeconds));
    }

    // -------------------------------------------------------------------------
    // Crawler DNS verification cache
    // -------------------------------------------------------------------------

    /**
     * Returns a cached crawler-verification verdict, or null when there is no
     * usable entry — missing, corrupt, or expired.
     *
     * A corrupt entry is treated as a miss rather than an error: the cost of
     * re-running the lookup is far smaller than failing the request.
     */
    public function readDnsCache(string $key): ?bool
    {
        $file = $this->dnsFile($key);
        $data = $this->readJson($file);

        if ($data === null
            || !isset($data['trusted'], $data['expires'])
            || !is_bool($data['trusted'])
            || !is_int($data['expires'])
        ) {
            return null;
        }

        if (time() > $data['expires']) {
            @unlink($file);
            return null;
        }

        return $data['trusted'];
    }

    /**
     * Stores a verification verdict. A $ttl of 0 or less disables caching for
     * this entry.
     *
     * Write failures are ignored on purpose — a cache that cannot be written
     * must degrade into extra DNS lookups, never into a broken request.
     */
    public function writeDnsCache(string $key, bool $trusted, int $ttl): void
    {
        if ($ttl <= 0) {
            return;
        }

        @file_put_contents($this->dnsFile($key), json_encode([
            'trusted'   => $trusted,
            'cached_at' => time(),
            'expires'   => time() + $ttl,
        ]), LOCK_EX);
    }

    public function deleteDnsCache(string $key): void
    {
        @unlink($this->dnsFile($key));
    }

    /**
     * Removes expired and unreadable cache entries. Safe to call from cron.
     */
    public function cleanupDnsCache(): void
    {
        foreach (glob($this->dir(self::DIR_DNS) . '/*.json') ?: [] as $file) {
            $data = $this->readJson($file);

            if ($data === null
                || !isset($data['expires'])
                || !is_int($data['expires'])
                || time() > $data['expires']
            ) {
                @unlink($file);
            }
        }
    }

    public function clearDnsCache(): void
    {
        foreach (glob($this->dir(self::DIR_DNS) . '/*.json') ?: [] as $file) {
            @unlink($file);
        }
    }

    // -------------------------------------------------------------------------
    // Logging
    // -------------------------------------------------------------------------

    public function appendLog(array $entry, int $maxSizeMb = 10): void
    {
        $file = $this->dir(self::DIR_LOGS) . '/attacks.log';

        // Rotate if oversized
        if (file_exists($file) && filesize($file) > $maxSizeMb * 1024 * 1024) {
            rename($file, $file . '.' . date('Ymd_His') . '.bak');
        }

        $line = date('Y-m-d H:i:s') . ' | ' . implode(' | ', [
            'ip='     . ($entry['ip']      ?? ''),
            'type='   . ($entry['type']    ?? ''),
            'uri='    . ($entry['uri']      ?? ''),
            'reason=' . ($entry['reason']  ?? ''),
            'ua='     . substr($entry['ua'] ?? '', 0, 80),
        ]) . PHP_EOL;

        file_put_contents($file, $line, FILE_APPEND | LOCK_EX);
    }

    public function readLogs(int $limit = 100): array
    {
        $file = $this->dir(self::DIR_LOGS) . '/attacks.log';
        if (!file_exists($file)) {
            return [];
        }

        $lines = file($file, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES);
        return array_slice(array_reverse($lines), 0, $limit);
    }

    public function cleanupLogs(int $keepDays = 30): void
    {
        $dir     = $this->dir(self::DIR_LOGS);
        $cutoff  = time() - ($keepDays * 86400);

        foreach (glob($dir . '/*.bak') as $file) {
            if (filemtime($file) < $cutoff) {
                @unlink($file);
            }
        }
    }

    // -------------------------------------------------------------------------
    // Path helpers
    // -------------------------------------------------------------------------

    public function basePath(): string
    {
        return $this->basePath;
    }

    public function logsPath(): string
    {
        return $this->dir(self::DIR_LOGS);
    }

    // -------------------------------------------------------------------------
    // Private helpers
    // -------------------------------------------------------------------------

    private function dir(string $sub): string
    {
        return $this->basePath . '/' . $sub;
    }

    private function banFile(string $ip): string
    {
        return $this->dir(self::DIR_BANS) . '/' . $this->safeFilename($ip) . '.json';
    }

    private function violationFile(string $ip): string
    {
        return $this->dir(self::DIR_VIOLATIONS) . '/' . $this->safeFilename($ip) . '.json';
    }

    private function rateFile(string $ip): string
    {
        return $this->dir(self::DIR_RATE) . '/' . $this->safeFilename($ip) . '.json';
    }

    /**
     * Cache keys are hashed rather than sanitized, so the filename is always
     * plain hex: no traversal, and no leading dot that would hide the entry
     * from the glob() used by cleanup.
     */
    private function dnsFile(string $key): string
    {
        return $this->dir(self::DIR_DNS) . '/' . sha1($key) . '.json';
    }

    private function safeFilename(string $ip): string
    {
        return preg_replace('/[^a-zA-Z0-9._\-]/', '_', $ip);
    }

    private function readBan(string $ip): ?array
    {
        return $this->readJson($this->banFile($ip));
    }

    private function writeBan(string $ip, array $data): void
    {
        $this->writeJson($this->banFile($ip), $data);
    }

    private function deleteBan(string $ip): void
    {
        @unlink($this->banFile($ip));
    }

    private function readJson(string $file): ?array
    {
        if (!file_exists($file)) {
            return null;
        }

        $content = file_get_contents($file);
        if ($content === false || $content === '') {
            return null;
        }

        $data = json_decode($content, true);
        return is_array($data) ? $data : null;
    }

    private function writeJson(string $file, array $data): void
    {
        file_put_contents($file, json_encode($data), LOCK_EX);
    }

    /**
     * Reads the timestamp list behind an already-locked handle and drops
     * entries older than $decayWindow.
     *
     * Also the self-heal path for a pre-decay-window violation file: an
     * object with count/first/last keys decodes to an array where 'count' is
     * far smaller than any real timestamp, so it is filtered out here and
     * only the genuine 'first'/'last' timestamps survive.
     *
     * @return array<int,int>
     */
    private function decayedTimestamps($handle, int $decayWindow): array
    {
        $contents = stream_get_contents($handle);
        $data     = is_string($contents) ? json_decode($contents, true) : null;
        $now      = time();

        if (!is_array($data)) {
            return [];
        }

        return array_values(array_filter(
            $data,
            fn($t): bool => is_int($t) && ($now - $t) < $decayWindow
        ));
    }

    /**
     * @param array<int,int> $timestamps
     */
    private function writeTimestamps($handle, array $timestamps): void
    {
        rewind($handle);
        ftruncate($handle, 0);
        fwrite($handle, json_encode($timestamps));
        fflush($handle);
    }

    private function ensureDirectories(): void
    {
        foreach ([self::DIR_BANS, self::DIR_RATE, self::DIR_VIOLATIONS, self::DIR_LOGS, self::DIR_DNS] as $sub) {
            $path = $this->dir($sub);
            if (!is_dir($path)) {
                mkdir($path, 0755, true);
            }
        }
    }
}
