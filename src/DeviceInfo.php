<?php

declare(strict_types=1);

namespace Webrium\XZeroProtect;

/**
 * Parses a User-Agent string and exposes browser, OS, and device information.
 *
 * Usage:
 *   $visit->device->browser        // 'Chrome'
 *   $visit->device->browserVersion // '124.0'
 *   $visit->device->os             // 'Windows'
 *   $visit->device->osVersion      // '10'
 *   $visit->device->type           // 'desktop' | 'mobile' | 'tablet'
 *   $visit->device->isMobile       // bool
 *   $visit->device->isTablet       // bool
 *   $visit->device->isDesktop      // bool
 */
class DeviceInfo
{
    public readonly string $browser;
    public readonly string $browserVersion;
    public readonly string $os;
    public readonly string $osVersion;
    public readonly string $type;        // 'desktop' | 'mobile' | 'tablet'
    public readonly bool   $isMobile;
    public readonly bool   $isTablet;
    public readonly bool   $isDesktop;

    public function __construct(string $userAgent)
    {
        $this->type           = $this->detectType($userAgent);
        $this->isMobile       = $this->type === 'mobile';
        $this->isTablet       = $this->type === 'tablet';
        $this->isDesktop      = $this->type === 'desktop';

        [$this->browser, $this->browserVersion] = $this->detectBrowser($userAgent);
        [$this->os, $this->osVersion]           = $this->detectOS($userAgent);
    }

    // -------------------------------------------------------------------------
    // Device type
    // -------------------------------------------------------------------------

    private function detectType(string $ua): string
    {
        $ua = strtolower($ua);

        // Tablet — check before mobile (iPad UA can contain "mobile" on newer iOS)
        if (
            str_contains($ua, 'tablet')  ||
            str_contains($ua, 'ipad')    ||
            (str_contains($ua, 'android') && !str_contains($ua, 'mobile'))
        ) {
            return 'tablet';
        }

        // Mobile
        if (
            str_contains($ua, 'mobile')     ||
            str_contains($ua, 'iphone')     ||
            str_contains($ua, 'ipod')       ||
            str_contains($ua, 'blackberry') ||
            str_contains($ua, 'windows phone')
        ) {
            return 'mobile';
        }

        return 'desktop';
    }

    // -------------------------------------------------------------------------
    // Browser detection
    // -------------------------------------------------------------------------

    private function detectBrowser(string $ua): array
    {
        // Order matters — more specific patterns first

        // Samsung Internet
        if (preg_match('/SamsungBrowser\/([\d.]+)/i', $ua, $m)) {
            return ['Samsung Internet', $m[1]];
        }

        // Edge (Chromium-based)
        if (preg_match('/Edg(?:e)?\/([\d.]+)/i', $ua, $m)) {
            return ['Edge', $m[1]];
        }

        // Opera (new)
        if (preg_match('/OPR\/([\d.]+)/i', $ua, $m)) {
            return ['Opera', $m[1]];
        }

        // Opera (old)
        if (preg_match('/Opera\/([\d.]+)/i', $ua, $m)) {
            return ['Opera', $m[1]];
        }

        // Brave — self-identifies via UA hint; without hints we can only flag
        // its UA looks identical to Chrome. We leave it as Chrome in that case.

        // Chrome / Chromium
        if (preg_match('/(?:Chrome|CrMo|CriOS)\/([\d.]+)/i', $ua, $m)) {
            return ['Chrome', $m[1]];
        }

        // Firefox
        if (preg_match('/(?:Firefox|FxiOS)\/([\d.]+)/i', $ua, $m)) {
            return ['Firefox', $m[1]];
        }

        // Safari (must come after Chrome/Edge/Opera because they include "Safari" too)
        if (preg_match('/Version\/([\d.]+).*Safari/i', $ua, $m)) {
            return ['Safari', $m[1]];
        }

        // IE 11
        if (str_contains($ua, 'Trident/')) {
            preg_match('/rv:([\d.]+)/i', $ua, $m);
            return ['Internet Explorer', $m[1] ?? '11'];
        }

        // IE <= 10
        if (preg_match('/MSIE ([\d.]+)/i', $ua, $m)) {
            return ['Internet Explorer', $m[1]];
        }

        return ['Unknown', ''];
    }

    // -------------------------------------------------------------------------
    // OS detection
    // -------------------------------------------------------------------------

    private function detectOS(string $ua): array
    {
        // iOS (iPhone/iPad) — before macOS
        if (preg_match('/(?:iPhone|iPad|iPod).*OS ([\d_]+)/i', $ua, $m)) {
            return ['iOS', str_replace('_', '.', $m[1])];
        }

        // macOS
        if (preg_match('/Mac OS X ([\d_]+)/i', $ua, $m)) {
            return ['macOS', str_replace('_', '.', $m[1])];
        }

        // Windows
        if (preg_match('/Windows NT ([\d.]+)/i', $ua, $m)) {
            $version = $this->windowsNtToVersion($m[1]);
            return ['Windows', $version];
        }

        // Windows Phone
        if (preg_match('/Windows Phone (?:OS )?([\d.]+)/i', $ua, $m)) {
            return ['Windows Phone', $m[1]];
        }

        // Android
        if (preg_match('/Android ([\d.]+)/i', $ua, $m)) {
            return ['Android', $m[1]];
        }

        // Linux
        if (str_contains($ua, 'Linux')) {
            // Ubuntu
            if (str_contains($ua, 'Ubuntu')) {
                return ['Ubuntu', ''];
            }
            return ['Linux', ''];
        }

        // ChromeOS
        if (str_contains($ua, 'CrOS')) {
            return ['ChromeOS', ''];
        }

        return ['Unknown', ''];
    }

    private function windowsNtToVersion(string $nt): string
    {
        return match ($nt) {
            '10.0' => '10/11',
            '6.3'  => '8.1',
            '6.2'  => '8',
            '6.1'  => '7',
            '6.0'  => 'Vista',
            '5.2'  => 'XP x64',
            '5.1'  => 'XP',
            default => $nt,
        };
    }
}
