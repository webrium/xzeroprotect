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

    public function __construct(Storage $storage, bool $enabled = true, int $maxSizeMb = 10, int $keepDays = 30)
    {
        $this->storage   = $storage;
        $this->enabled   = $enabled;
        $this->maxSizeMb = $maxSizeMb;
        $this->keepDays  = $keepDays;
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
    }

    public function recent(int $limit = 100): array
    {
        return $this->storage->readLogs($limit);
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
