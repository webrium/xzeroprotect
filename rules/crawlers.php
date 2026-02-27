<?php

/**
 * Trusted web crawler / bot User-Agent signatures.
 *
 * These bots are legitimate and should NOT be blocked or rate-limited.
 * Each entry contains:
 *   - ua_contains : substring matched (case-insensitive) against User-Agent header
 *   - verify_rdns : whether to confirm identity via reverse DNS lookup (recommended)
 *   - rdns_suffix : the expected hostname suffix returned by reverse DNS
 *   - name        : human-readable label for logging
 *
 * HOW CRAWLER VERIFICATION WORKS
 * ───────────────────────────────
 * Anyone can fake a User-Agent. Real verification requires a reverse DNS check:
 *   1. Resolve the visitor IP to a hostname  (gethostbyaddr)
 *   2. Confirm the hostname ends with the expected suffix
 *   3. Re-resolve that hostname back to an IP  (gethostbyname)
 *   4. Confirm the re-resolved IP matches the original visitor IP
 * Only if all four steps pass is the crawler considered genuine.
 *
 * This is the method recommended by Google, Bing, and others in their
 * official documentation. DNS results are cached in memory per request.
 */
return [

    // ── Search engines ─────────────────────────────────────────────────────────

    [
        'name'        => 'Googlebot',
        'ua_contains' => 'googlebot',
        'verify_rdns' => true,
        'rdns_suffix' => '.googlebot.com',
    ],
    [
        'name'        => 'Google Other (APIs, AdsBot, etc.)',
        'ua_contains' => 'google',
        'verify_rdns' => true,
        'rdns_suffix' => '.google.com',
    ],
    [
        'name'        => 'Bingbot',
        'ua_contains' => 'bingbot',
        'verify_rdns' => true,
        'rdns_suffix' => '.search.msn.com',
    ],
    [
        'name'        => 'Yahoo Slurp',
        'ua_contains' => 'yahoo! slurp',
        'verify_rdns' => true,
        'rdns_suffix' => '.crawl.yahoo.net',
    ],
    [
        'name'        => 'DuckDuckBot',
        'ua_contains' => 'duckduckbot',
        'verify_rdns' => false,   // DuckDuckGo does not publish rDNS suffix
        'rdns_suffix' => '',
    ],
    [
        'name'        => 'Yandex',
        'ua_contains' => 'yandexbot',
        'verify_rdns' => true,
        'rdns_suffix' => '.yandex.com',
    ],
    [
        'name'        => 'Yandex (RU)',
        'ua_contains' => 'yandex.ru',
        'verify_rdns' => true,
        'rdns_suffix' => '.yandex.ru',
    ],
    [
        'name'        => 'Baidu',
        'ua_contains' => 'baiduspider',
        'verify_rdns' => true,
        'rdns_suffix' => '.baidu.com',
    ],
    [
        'name'        => 'Sogou',
        'ua_contains' => 'sogou',
        'verify_rdns' => true,
        'rdns_suffix' => '.sogou.com',
    ],
    [
        'name'        => 'Exabot',
        'ua_contains' => 'exabot',
        'verify_rdns' => true,
        'rdns_suffix' => '.exabot.com',
    ],

    // ── Social / preview crawlers ───────────────────────────────────────────────

    [
        'name'        => 'Facebook',
        'ua_contains' => 'facebookexternalhit',
        'verify_rdns' => true,
        'rdns_suffix' => '.facebook.com',
    ],
    [
        'name'        => 'Twitter / X',
        'ua_contains' => 'twitterbot',
        'verify_rdns' => false,
        'rdns_suffix' => '',
    ],
    [
        'name'        => 'LinkedInBot',
        'ua_contains' => 'linkedinbot',
        'verify_rdns' => false,
        'rdns_suffix' => '',
    ],
    [
        'name'        => 'WhatsApp',
        'ua_contains' => 'whatsapp',
        'verify_rdns' => false,
        'rdns_suffix' => '',
    ],
    [
        'name'        => 'Telegram',
        'ua_contains' => 'telegrambot',
        'verify_rdns' => false,
        'rdns_suffix' => '',
    ],
    [
        'name'        => 'Slack',
        'ua_contains' => 'slackbot',
        'verify_rdns' => false,
        'rdns_suffix' => '',
    ],
    [
        'name'        => 'Discord',
        'ua_contains' => 'discordbot',
        'verify_rdns' => false,
        'rdns_suffix' => '',
    ],

    // ── Infrastructure / monitoring ─────────────────────────────────────────────

    [
        'name'        => 'Apple',
        'ua_contains' => 'applebot',
        'verify_rdns' => true,
        'rdns_suffix' => '.applebot.apple.com',
    ],
    [
        'name'        => 'Uptimerobot',
        'ua_contains' => 'uptimerobot',
        'verify_rdns' => false,
        'rdns_suffix' => '',
    ],
    [
        'name'        => 'Pingdom',
        'ua_contains' => 'pingdom',
        'verify_rdns' => false,
        'rdns_suffix' => '',
    ],

];
