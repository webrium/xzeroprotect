<?php

declare(strict_types=1);

namespace Webrium\XZeroProtect;

/**
 * Sliding-window rate limiter backed by file storage.
 */
class RateLimiter
{
    private Storage $storage;
    private int     $maxRequests;
    private int     $perSeconds;

    public function __construct(Storage $storage, int $maxRequests = 60, int $perSeconds = 60)
    {
        $this->storage     = $storage;
        $this->maxRequests = $maxRequests;
        $this->perSeconds  = $perSeconds;
    }

    /**
     * Track the request and return true if limit is exceeded.
     */
    public function isExceeded(string $ip): bool
    {
        $count = $this->storage->trackRequest($ip, $this->perSeconds);
        return $count > $this->maxRequests;
    }

    /**
     * Get current request count without recording a new hit.
     */
    public function getCount(string $ip): int
    {
        return $this->storage->getRateCount($ip, $this->perSeconds);
    }

    public function setMaxRequests(int $max): void
    {
        $this->maxRequests = $max;
    }

    public function setWindow(int $seconds): void
    {
        $this->perSeconds = $seconds;
    }

    public function getMaxRequests(): int
    {
        return $this->maxRequests;
    }

    public function getWindow(): int
    {
        return $this->perSeconds;
    }
}
