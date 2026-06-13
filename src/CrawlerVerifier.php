<?php

declare(strict_types=1);

namespace Webrium\XZeroProtect;

/**
 * Identifies and optionally verifies trusted web crawlers.
 *
 * Verification uses the double-DNS method recommended by Google and Bing:
 *   1. gethostbyaddr($ip)          → hostname
 *   2. check hostname ends with expected suffix
 *   3. gethostbyname($hostname)    → re-resolved IP
 *   4. confirm re-resolved IP === original IP
 *
 * DNS lookups are cached in-memory for the lifetime of the request.
 */
class CrawlerVerifier
{
    /** @var array<array{name:string, ua_contains:string, verify_rdns:bool, rdns_suffix:string}> */
    private array $crawlers = [];

    /** In-memory DNS cache: ip → hostname */
    private array $dnsCache = [];

    public function __construct(string $rulesDir)
    {
        $this->crawlers = require $rulesDir . '/crawlers.php';
    }

    // -------------------------------------------------------------------------
    // Public API
    // -------------------------------------------------------------------------

    /**
     * Returns true if the request is a trusted crawler.
     *
     * When verify_rdns is true for the matched crawler, the IP is confirmed
     * via reverse DNS before granting trust. If DNS verification fails, the
     * request is treated as a spoofed crawler UA and NOT trusted.
     */
    public function isTrustedCrawler(string $ip, string $userAgent): bool
    {
        if (trim($userAgent) === '') {
            return false;
        }

        $ua      = strtolower($userAgent);
        $matched = $this->matchCrawler($ua);

        if ($matched === null) {
            return false;
        }

        // If this crawler requires rDNS verification, do it
        if ($matched['verify_rdns'] && $matched['rdns_suffix'] !== '') {
            return $this->verifyViaDns($ip, $matched['rdns_suffix']);
        }

        // No rDNS check required — UA match is sufficient
        return true;
    }

    /**
     * Returns the crawler name if UA matches, or null.
     * Does NOT perform DNS verification — use isTrustedCrawler() for that.
     */
    public function getCrawlerName(string $userAgent): ?string
    {
        $matched = $this->matchCrawler(strtolower($userAgent));
        return $matched['name'] ?? null;
    }

    /**
     * Add a custom trusted crawler entry at runtime.
     */
    public function addCrawler(string $name, string $uaContains, bool $verifyRdns = false, string $rdnsSuffix = ''): void
    {
        $this->crawlers[] = [
            'name'        => $name,
            'ua_contains' => strtolower($uaContains),
            'verify_rdns' => $verifyRdns,
            'rdns_suffix' => $rdnsSuffix,
        ];
    }

    /**
     * Remove a crawler by name.
     */
    public function removeCrawler(string $name): void
    {
        $this->crawlers = array_values(array_filter(
            $this->crawlers,
            fn($c) => strtolower($c['name']) !== strtolower($name)
        ));
    }

    public function getCrawlers(): array
    {
        return $this->crawlers;
    }

    // -------------------------------------------------------------------------
    // Private helpers
    // -------------------------------------------------------------------------

    private function matchCrawler(string $uaLower): ?array
    {
        foreach ($this->crawlers as $crawler) {
            if (strpos($uaLower, strtolower($crawler['ua_contains'])) !== false) {
                return $crawler;
            }
        }
        return null;
    }

    /**
     * Double-DNS verification:
     *  ip → hostname (must end with $suffix)
     *  hostname → ip (must match original ip, IPv4 or IPv6)
     */
    private function verifyViaDns(string $ip, string $suffix): bool
    {
        // Step 1: reverse lookup
        $hostname = $this->reverseLookup($ip);
        if ($hostname === null || $hostname === $ip) {
            return false; // no PTR record
        }

        // Step 2: suffix check
        if (!str_ends_with(strtolower($hostname), strtolower($suffix))) {
            return false;
        }

        // Step 3 & 4: forward lookup — confirm hostname resolves back to the
        // original IP. We must check both A (IPv4) and AAAA (IPv6) records,
        // because crawlers increasingly connect over IPv6 and gethostbyname()
        // only returns IPv4 addresses. Both sides are normalized so differing
        // IPv6 text representations still compare equal.
        return in_array($this->normalizeIp($ip), $this->forwardLookup($hostname), true);
    }

    /**
     * Resolve a hostname to all of its A and AAAA records.
     *
     * @return array<int,string> List of resolved IPs (IPv4 + IPv6), normalized.
     */
    private function forwardLookup(string $hostname): array
    {
        $ips = [];

        // dns_get_record gives us both IPv4 (A) and IPv6 (AAAA) records.
        // Suppress errors: it can emit warnings on lookup failure.
        $records = @dns_get_record($hostname, DNS_A | DNS_AAAA);

        if (is_array($records)) {
            foreach ($records as $record) {
                if (isset($record['ip'])) {            // A record
                    $ips[] = $this->normalizeIp($record['ip']);
                } elseif (isset($record['ipv6'])) {    // AAAA record
                    $ips[] = $this->normalizeIp($record['ipv6']);
                }
            }
        }

        // Fallback to gethostbyname() (IPv4 only) if dns_get_record is
        // unavailable or returned nothing.
        if (empty($ips)) {
            $resolved = gethostbyname($hostname);
            if ($resolved !== $hostname) {
                $ips[] = $this->normalizeIp($resolved);
            }
        }

        return $ips;
    }

    /**
     * Normalize an IP to its canonical binary form for reliable comparison
     * (handles differing IPv6 text representations, e.g. 2001:db8::1 vs
     * 2001:0db8:0000::1). Falls back to the original string if invalid.
     */
    private function normalizeIp(string $ip): string
    {
        $packed = @inet_pton($ip);
        return $packed === false ? $ip : (inet_ntop($packed) ?: $ip);
    }

    private function reverseLookup(string $ip): ?string
    {
        if (isset($this->dnsCache[$ip])) {
            return $this->dnsCache[$ip];
        }

        $hostname = gethostbyaddr($ip);

        // gethostbyaddr returns false on failure, or the IP string if no PTR exists
        if ($hostname === false || $hostname === $ip) {
            $this->dnsCache[$ip] = null;
            return null;
        }

        $this->dnsCache[$ip] = $hostname;
        return $hostname;
    }
}
