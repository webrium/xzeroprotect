<?php

declare(strict_types=1);

namespace Webrium\XZeroProtect;

/**
 * Represents the current HTTP request.
 */
class Request
{
    public readonly string $ip;
    public readonly string $uri;
    public readonly string $method;
    public readonly string $userAgent;
    public readonly string $referer;
    public readonly array  $get;
    public readonly array  $post;
    public readonly array  $cookies;
    public readonly float  $time;

    /**
     * Headers (in order of preference) that may carry the real client IP
     * when the request passes through a trusted reverse proxy / CDN.
     *
     * CF-Connecting-IP is listed first because, when present, it is set by
     * Cloudflare's edge and cannot be spoofed by the end client.
     */
    private const PROXY_HEADERS = [
        'HTTP_CF_CONNECTING_IP',
        'HTTP_TRUE_CLIENT_IP',
        'HTTP_X_REAL_IP',
        'HTTP_X_FORWARDED_FOR',
    ];

    /**
     * @param array<int,string> $trustedProxies List of IPs/CIDRs for proxies
     *        (e.g. load balancers, CDNs) that are allowed to set client-IP
     *        headers. If REMOTE_ADDR matches one of these, headers from
     *        PROXY_HEADERS are trusted to determine the real client IP.
     *        Pass ['*'] to trust any REMOTE_ADDR (use only when the server
     *        is unreachable except through the proxy/CDN, e.g. Cloudflare
     *        with "no direct IP access" enabled).
     */
    public function __construct(array $trustedProxies = [])
    {
        $this->ip        = $this->resolveIp($trustedProxies);
        $this->uri       = $_SERVER['REQUEST_URI']       ?? '/';
        $this->method    = strtoupper($_SERVER['REQUEST_METHOD'] ?? 'GET');
        $this->userAgent = $_SERVER['HTTP_USER_AGENT']   ?? '';
        $this->referer   = $_SERVER['HTTP_REFERER']      ?? '';
        $this->get       = $_GET    ?? [];
        $this->post      = $_POST   ?? [];
        $this->cookies   = $_COOKIE ?? [];
        $this->time      = microtime(true);
    }

    /**
     * Resolve the real client IP.
     *
     * By default (no trusted proxies configured) this returns REMOTE_ADDR,
     * which is the only value that cannot be spoofed by the client.
     *
     * When $trustedProxies is non-empty and REMOTE_ADDR matches one of the
     * given IPs/CIDRs (or the list contains '*'), the first valid public IP
     * found in PROXY_HEADERS is used instead — this is required for sites
     * behind Cloudflare, Nginx reverse proxies, load balancers, etc.
     */
    private function resolveIp(array $trustedProxies): string
    {
        $remoteAddr = $_SERVER['REMOTE_ADDR'] ?? '0.0.0.0';

        if (empty($trustedProxies) || !$this->isTrustedProxy($remoteAddr, $trustedProxies)) {
            return $remoteAddr;
        }

        foreach (self::PROXY_HEADERS as $header) {
            if (empty($_SERVER[$header])) {
                continue;
            }

            // X-Forwarded-For can contain a comma-separated chain;
            // the left-most entry is the original client.
            $candidates = array_map('trim', explode(',', $_SERVER[$header]));

            foreach ($candidates as $candidate) {
                if (filter_var($candidate, FILTER_VALIDATE_IP)) {
                    return $candidate;
                }
            }
        }

        return $remoteAddr;
    }

    /**
     * Returns true if $ip matches any entry in $trustedProxies.
     * Supports exact IPs, CIDR ranges, and '*' (trust any).
     */
    private function isTrustedProxy(string $ip, array $trustedProxies): bool
    {
        foreach ($trustedProxies as $entry) {
            if ($entry === '*') {
                return true;
            }

            if (strpos($entry, '/') === false) {
                if ($this->ipEquals($ip, $entry)) {
                    return true;
                }
                continue;
            }

            if ($this->ipInCidr($ip, $entry)) {
                return true;
            }
        }

        return false;
    }

    /**
     * Compares two IPs for equality using their canonical binary form, so
     * differing IPv6 text representations (e.g. 2001:db8::1 vs
     * 2001:0db8:0000::1) still compare equal. Falls back to string compare
     * for non-IP values.
     */
    private function ipEquals(string $a, string $b): bool
    {
        $packedA = @inet_pton($a);
        $packedB = @inet_pton($b);

        if ($packedA === false || $packedB === false) {
            return $a === $b;
        }

        return $packedA === $packedB;
    }

    private function ipInCidr(string $ip, string $cidr): bool
    {
        [$subnet, $bits] = explode('/', $cidr, 2);
        $bits = (int) $bits;

        if (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4)
            && filter_var($subnet, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4)) {
            $ipLong     = ip2long($ip);
            $subnetLong = ip2long($subnet);
            $mask       = $bits === 0 ? 0 : (~0 << (32 - $bits));
            return ($ipLong & $mask) === ($subnetLong & $mask);
        }

        if (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6)
            && filter_var($subnet, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6)) {
            $ipBin     = inet_pton($ip);
            $subnetBin = inet_pton($subnet);
            if ($ipBin === false || $subnetBin === false) {
                return false;
            }

            $mask = str_repeat("\xff", (int) ($bits / 8));
            $remainder = $bits % 8;
            if ($remainder > 0) {
                $mask .= chr(0xff << (8 - $remainder));
            }
            $mask = str_pad($mask, 16, "\x00");

            return ($ipBin & $mask) === ($subnetBin & $mask);
        }

        return false;
    }

    /**
     * Returns all user-supplied input as a flat string for payload scanning.
     */
    public function rawInput(): string
    {
        $parts = [];

        foreach ([$this->get, $this->post, $this->cookies] as $bag) {
            foreach ($bag as $value) {
                $parts[] = is_array($value) ? implode(' ', $value) : (string) $value;
            }
        }

        // Also include raw POST body (for JSON APIs, etc.)
        $raw = file_get_contents('php://input');
        if ($raw !== false && $raw !== '') {
            $parts[] = $raw;
        }

        return implode(' ', $parts);
    }

    /**
     * Returns the path portion of the URI (without query string).
     */
    public function path(): string
    {
        return parse_url($this->uri, PHP_URL_PATH) ?? $this->uri;
    }
}
