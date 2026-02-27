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

    public function incrementViolation(string $ip): int
    {
        $file  = $this->violationFile($ip);
        $data  = $this->readJson($file) ?? ['count' => 0, 'first' => time()];
        $data['count']++;
        $data['last'] = time();
        $this->writeJson($file, $data);
        return $data['count'];
    }

    public function getViolationCount(string $ip): int
    {
        $data = $this->readJson($this->violationFile($ip));
        return $data['count'] ?? 0;
    }

    public function resetViolations(string $ip): void
    {
        @unlink($this->violationFile($ip));
    }

    // -------------------------------------------------------------------------
    // Rate limiting
    // -------------------------------------------------------------------------

    /**
     * Increments request counter for $ip within a sliding window.
     * Returns the current count within the window.
     */
    public function trackRequest(string $ip, int $windowSeconds): int
    {
        $file   = $this->rateFile($ip);
        $now    = time();
        $data   = $this->readJson($file) ?? [];

        // Remove timestamps outside the window
        $data = array_filter($data, fn($t) => ($now - $t) < $windowSeconds);
        $data[] = $now;

        $this->writeJson($file, array_values($data));
        return count($data);
    }

    public function getRateCount(string $ip, int $windowSeconds): int
    {
        $file = $this->rateFile($ip);
        $now  = time();
        $data = $this->readJson($file) ?? [];
        return count(array_filter($data, fn($t) => ($now - $t) < $windowSeconds));
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

    private function ensureDirectories(): void
    {
        foreach ([self::DIR_BANS, self::DIR_RATE, self::DIR_VIOLATIONS, self::DIR_LOGS] as $sub) {
            $path = $this->dir($sub);
            if (!is_dir($path)) {
                mkdir($path, 0755, true);
            }
        }
    }
}
