<?php

return [

    /*
    |--------------------------------------------------------------------------
    | Firewall Mode
    |--------------------------------------------------------------------------
    | production : block & log attacks
    | learning   : only log, never block (for tuning rules)
    | off        : disabled entirely
    */
    'mode' => 'production',

    /*
    |--------------------------------------------------------------------------
    | Storage Path
    |--------------------------------------------------------------------------
    | Where logs, banned IPs, and rate-limit data are stored.
    */
    'storage_path' => null, // null = auto: package_dir/storage

    /*
    |--------------------------------------------------------------------------
    | Apache / .htaccess Blocking
    |--------------------------------------------------------------------------
    | Sync permanently banned IPs into .htaccess so Apache blocks them
    | before PHP runs, saving server resources.
    */
    'apache_blocking' => false,
    'htaccess_path'   => null, // null = auto-detect (DOCUMENT_ROOT/.htaccess)

    /*
    |--------------------------------------------------------------------------
    | Auto-Ban Settings
    |--------------------------------------------------------------------------
    | violations_threshold : violations within violation_window before a ban
    | violation_window      : rolling window (seconds) violations are counted
    |                         in — an old, one-off violation ages out instead
    |                         of counting against a client forever
    | ban_duration          : seconds, 0 = permanent
    | permanent_after_bans  : temp bans before escalating to permanent
    |
    | A rate-limit violation is recorded at most once per rate-limit window
    | (see 'rate_limit' below), no matter how many individual requests
    | overflowed it — a single bursty page load must not, by itself, add up
    | to a ban. Sustained flooding still racks up one violation every window.
    */
    'auto_ban' => [
        'enabled'              => true,
        'violations_threshold' => 10,
        'violation_window'     => 3600,
        'ban_duration'         => 86400,
        'permanent_after_bans' => 3,
    ],

    /*
    |--------------------------------------------------------------------------
    | Rate Limiting
    |--------------------------------------------------------------------------
    */
    'rate_limit' => [
        'enabled'      => true,
        'max_requests' => 60,
        'per_seconds'  => 60,
    ],

    /*
    |--------------------------------------------------------------------------
    | Empty User-Agent
    |--------------------------------------------------------------------------
    | Feed readers, uptime probes, and some proxies send no User-Agent header.
    | An absent UA is unusual, not hostile, so it does not count as a violation
    | by default — treating it as one fed auto_ban with legitimate clients.
    | Enable only if every client of this app is known to send a UA.
    */
    'empty_user_agent_suspicious' => false,

    /*
    |--------------------------------------------------------------------------
    | Checks — enable/disable individual detection modules
    |--------------------------------------------------------------------------
    */
    'checks' => [
        'crawler_check' => true,   // identify & exempt trusted crawlers (Googlebot, Bingbot, etc.)
        'rate_limit'    => true,
        'blocked_path'  => true,
        'user_agent'    => true,
        'payload'       => true,
        'custom_rules'  => true,
    ],

    /*
    |--------------------------------------------------------------------------
    | Payload Scanning
    |--------------------------------------------------------------------------
    | Configure input sources and field exemptions for payload detection.
    |
    | exempt_fields : field/parameter names to exclude from payload inspection
    |                 (e.g., ['content', 'body', 'description', 'message', 'code'])
    | sources       : sources to scan. Default: ['get', 'post', 'cookies', 'raw']
    */
    'payload_scan' => [
        'exempt_fields' => [],
        'sources'       => ['get', 'post', 'cookies', 'raw'],
    ],

    /*
    |--------------------------------------------------------------------------
    | Crawler Verification
    |--------------------------------------------------------------------------
    | When verify_rdns is true in crawlers.php, a double-DNS check is performed
    | to confirm the crawler is genuine (not a spoofed User-Agent).
    | Disable this only if your server cannot perform outbound DNS lookups.
    */
    'crawler_verify_dns' => true,

    /*
    |--------------------------------------------------------------------------
    | Crawler Verification Cache
    |--------------------------------------------------------------------------
    | Double-DNS verification costs two blocking network round-trips — often
    | several hundred milliseconds during which a PHP worker does nothing but
    | wait. Verdicts are cached on disk per IP + expected rDNS suffix.
    |
    | Failed verifications use the shorter negative_ttl so a transient resolver
    | outage cannot lock a legitimate crawler out for a full day, while still
    | absorbing floods of spoofed crawler User-Agents.
    */
    'crawler_cache' => [
        'enabled'      => true,
        'ttl'          => 86400,   // verified crawler (24h)
        'negative_ttl' => 3600,    // failed verification (1h)
    ],

    /*
    |--------------------------------------------------------------------------
    | Trusted Proxies
    |--------------------------------------------------------------------------
    | IPs/CIDRs of reverse proxies, load balancers, or CDNs (e.g. Cloudflare)
    | that sit in front of this server. When the immediate REMOTE_ADDR matches
    | one of these, the real client IP is read from CF-Connecting-IP,
    | True-Client-IP, X-Real-IP, or X-Forwarded-For (in that order).
    |
    | Leave empty (default) to always use REMOTE_ADDR — the safest option when
    | the server is directly reachable, since these headers can otherwise be
    | spoofed by the client.
    |
    | Use ['*'] to trust these headers regardless of REMOTE_ADDR — only do
    | this if the server is NOT directly reachable (e.g. firewalled to only
    | accept traffic from Cloudflare).
    */
    'trusted_proxies' => [],

    /*
    |--------------------------------------------------------------------------
    | Whitelists
    |--------------------------------------------------------------------------
    */
    'whitelist' => [
        'ips'   => [],          // e.g. ['127.0.0.1', '10.0.0.0/8']
        'paths' => [],          // e.g. ['/health', '/ping']
    ],

    /*
    |--------------------------------------------------------------------------
    | Response
    |--------------------------------------------------------------------------
    */
    'block_response' => [
        'code'    => 403,
        'message' => 'Access Denied',
    ],

    /*
    |--------------------------------------------------------------------------
    | Visitor Tracking Filter
    |--------------------------------------------------------------------------
    | Decides which of the requests that passed the firewall count as a real
    | page visit. Nothing here ever blocks a request — it only keeps assets,
    | favicons, and non-page methods out of your visit statistics.
    |
    | filter             : false restores pre-filter behaviour (record everything)
    | when               : 'immediate' fires during run(); 'shutdown' waits until
    |                      the response is finished so the HTTP status is known
    | only_status        : response codes that count as a visit — 'shutdown'
    |                      only; [] records regardless of the response
    | methods            : methods that may count as a visit; [] accepts any
    | use_sec_fetch_dest : trust the browser's own statement of intent
    | track_dest         : Sec-Fetch-Dest values that may count as a page
    | ignore_ajax        : skip XMLHttpRequest calls
    | ignore_prefetch    : skip speculative prefetch / prerender loads
    | ignore_extensions  : added to the defaults in rules/ignore_tracking.php
    | ignore_paths       : added to the defaults; matched as a path prefix
    |
    | Sec-Fetch-Dest can only reject a request, never wave one through: a page
    | navigation to a path you ignored on purpose stays ignored.
    */
    'tracking' => [
        'filter'             => true,
        'when'               => 'immediate',
        'only_status'        => [200],
        'methods'            => ['GET'],
        'use_sec_fetch_dest' => true,
        'track_dest'         => ['document'],
        'ignore_ajax'        => true,
        'ignore_prefetch'    => true,
        'ignore_extensions'  => [],
        'ignore_paths'       => [],
    ],

    /*
    |--------------------------------------------------------------------------
    | Logging
    |--------------------------------------------------------------------------
    | auto_cleanup : sweep rotated .bak files older than keep_days, driven by
    |                real log-write traffic (at most once/day) instead of a
    |                system cron. Turn off only if you already run your own
    |                cleanup (cron, logrotate, ...) and want to skip the check.
    */
    'log' => [
        'enabled'        => true,
        'max_file_size'  => 10,   // MB — rotate when exceeded
        'keep_days'      => 30,
        'auto_cleanup'   => true,
    ],

];