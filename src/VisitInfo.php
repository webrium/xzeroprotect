<?php

declare(strict_types=1);

namespace Webrium\XZeroProtect;

/**
 * Represents a verified real visit that passed all firewall checks.
 *
 * All properties are read-only. Access them directly:
 *   $visit->ip
 *   $visit->uri
 *   $visit->fingerprint
 *   $visit->browser->name  etc.
 */
class VisitInfo
{
    public readonly string      $ip;
    public readonly string      $uri;
    public readonly string      $path;
    public readonly string      $method;
    public readonly string      $userAgent;
    public readonly string      $referer;
    public readonly int         $timestamp;
    public readonly string      $fingerprint;   // unique visitor identifier
    public readonly DeviceInfo  $device;        // browser / OS / device type

    public function __construct(Request $request)
    {
        $this->ip          = $request->ip;
        $this->uri         = $request->uri;
        $this->path        = $request->path();
        $this->method      = $request->method;
        $this->userAgent   = $request->userAgent;
        $this->referer     = $request->referer;
        $this->timestamp   = time();
        $this->device      = new DeviceInfo($request->userAgent);
        $this->fingerprint = $this->buildFingerprint($request);
    }

    // -------------------------------------------------------------------------
    // Helpers
    // -------------------------------------------------------------------------

    /**
     * Returns timestamp formatted as a date string.
     * Default: 'Y-m-d H:i:s'
     */
    public function date(string $format = 'Y-m-d H:i:s'): string
    {
        return date($format, $this->timestamp);
    }

    /**
     * Returns all data as a plain array — useful for database inserts.
     *
     * Example:
     *   $pdo->prepare("INSERT INTO visits ...")
     *       ->execute($visit->toArray());
     */
    public function toArray(): array
    {
        return [
            'ip'          => $this->ip,
            'uri'         => $this->uri,
            'path'        => $this->path,
            'method'      => $this->method,
            'user_agent'  => $this->userAgent,
            'referer'     => $this->referer,
            'timestamp'   => $this->timestamp,
            'fingerprint' => $this->fingerprint,
            // device
            'browser'     => $this->device->browser,
            'browser_ver' => $this->device->browserVersion,
            'os'          => $this->device->os,
            'os_ver'      => $this->device->osVersion,
            'device_type' => $this->device->type,
            'is_mobile'   => $this->device->isMobile,
            'is_tablet'   => $this->device->isTablet,
            'is_desktop'  => $this->device->isDesktop,
        ];
    }

    // -------------------------------------------------------------------------
    // Private
    // -------------------------------------------------------------------------

    /**
     * Builds a privacy-safe fingerprint for unique visitor identification.
     *
     * Combines IP + User-Agent + today's date so the same person
     * on the same day gets the same fingerprint, but it resets daily
     * and cannot be reversed to reveal the original IP.
     */
    private function buildFingerprint(Request $request): string
    {
        $raw = implode('|', [
            $request->ip,
            $request->userAgent,
            date('Y-m-d'),   // resets daily — good balance between tracking & privacy
        ]);

        return hash('sha256', $raw);
    }
}
