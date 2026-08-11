<?php

declare(strict_types=1);

namespace Webrium\XZeroProtect;

/**
 * Attack logger.
 */
class Logger
{
    private Storage $storage;
    private bool    $enabled;
    private int     $maxSizeMb;
    private int     $keepDays;
    private bool    $autoCleanup;

    public function __construct(
        Storage $storage,
        bool $enabled = true,
        int $maxSizeMb = 10,
        int $keepDays = 30,
        bool $autoCleanup = true
    ) {
        $this->storage     = $storage;
        $this->enabled     = $enabled;
        $this->maxSizeMb   = $maxSizeMb;
        $this->keepDays    = $keepDays;
        $this->autoCleanup = $autoCleanup;
    }

    public function log(string $type, Request $request, string $reason = ''): void
    {
        if (!$this->enabled) {
            return;
        }

        $this->storage->appendLog([
            'ip'     => $request->ip,
            'type'   => $type,
            'uri'    => $request->uri,
            'reason' => $reason,
            'ua'     => $request->userAgent,
            'method' => $request->method,
        ], $this->maxSizeMb);

        // Driven by real log-write traffic instead of a system cron —
        // dueForLogCleanup() is a cheap check, gated to run at most once a
        // day, so this adds no meaningful cost to the (already rare)
        // attack-logging path.
        if ($this->autoCleanup && $this->storage->dueForLogCleanup()) {
            $this->cleanup();
        }
    }

    public function recent(int $limit = 100, int $offset = 0): array
    {
        return $this->storage->readLogs($limit, $offset);
    }

    /**
     * Total number of lines currently in the active log file (excludes
     * rotated .bak history) — for building pagination without reading
     * every line.
     */
    public function total(): int
    {
        return $this->storage->countLogLines();
    }

    public function cleanup(): void
    {
        $this->storage->cleanupLogs($this->keepDays);
    }

    public function setEnabled(bool $enabled): void
    {
        $this->enabled = $enabled;
    }
}
