<?php

declare(strict_types=1);

namespace Webrium\XZeroProtect;

/**
 * Manages IP banning, whitelisting, and CIDR matching.
 */
class IPManager
{
    private Storage $storage;
    private array   $whitelist = [];

    public function __construct(Storage $storage)
    {
        $this->storage = $storage;
    }

    // -------------------------------------------------------------------------
    // Whitelist
    // -------------------------------------------------------------------------

    public function whitelist(string $cidrOrIp): void
    {
        $this->whitelist[] = $cidrOrIp;
    }

    public function isWhitelisted(string $ip): bool
    {
        foreach ($this->whitelist as $entry) {
            if ($this->matches($ip, $entry)) {
                return true;
            }
        }
        return false;
    }

    // -------------------------------------------------------------------------
    // Banning
    // -------------------------------------------------------------------------

    public function ban(string $ip, string $reason = '', int $duration = 86400): void
    {
        $this->storage->ban($ip, $reason, $duration);
    }

    public function banPermanent(string $ip, string $reason = ''): void
    {
        $this->storage->ban($ip, $reason, 0);
    }

    public function unban(string $ip): void
    {
        $this->storage->unban($ip);
        $this->storage->resetViolations($ip);
    }

    public function isBanned(string $ip): bool
    {
        return $this->storage->isBanned($ip);
    }

    public function getBanInfo(string $ip): ?array
    {
        return $this->storage->getBanInfo($ip);
    }

    public function getAllBans(): array
    {
        return $this->storage->getAllBans();
    }

    // -------------------------------------------------------------------------
    // CIDR / range matching
    // -------------------------------------------------------------------------

    /**
     * Returns true if $ip matches $cidrOrIp (exact match or CIDR notation).
     */
    public function matches(string $ip, string $cidrOrIp): bool
    {
        if (strpos($cidrOrIp, '/') === false) {
            return $ip === $cidrOrIp;
        }

        return $this->ipInCidr($ip, $cidrOrIp);
    }

    private function ipInCidr(string $ip, string $cidr): bool
    {
        [$subnet, $bits] = explode('/', $cidr, 2);
        $bits = (int) $bits;

        // IPv4
        if (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4)
            && filter_var($subnet, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4)) {
            $ip_long     = ip2long($ip);
            $subnet_long = ip2long($subnet);
            $mask        = $bits === 0 ? 0 : (~0 << (32 - $bits));
            return ($ip_long & $mask) === ($subnet_long & $mask);
        }

        // IPv6
        if (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6)
            && filter_var($subnet, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6)) {
            $ip_bin     = inet_pton($ip);
            $subnet_bin = inet_pton($subnet);
            if ($ip_bin === false || $subnet_bin === false) {
                return false;
            }
            // Build mask
            $mask = str_repeat("\xff", (int)($bits / 8));
            $remainder = $bits % 8;
            if ($remainder > 0) {
                $mask .= chr(0xff << (8 - $remainder));
            }
            $mask = str_pad($mask, 16, "\x00");

            return ($ip_bin & $mask) === ($subnet_bin & $mask);
        }

        return false;
    }
}
