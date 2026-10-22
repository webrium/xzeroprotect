<?php

/**
 * Non-human visitors that are not attackers.
 *
 * Used only to label a visit as a bot for the tracking callback — nothing here
 * ever blocks a request. Trusted crawlers (rules/crawlers.php) are named from
 * that list; this file covers everything else: uptime monitors, HTTP clients,
 * headless browsers, link-preview fetchers and the long tail of unknown bots.
 *
 * Accuracy rule, same as the rest of the library: a human counted as a bot
 * silently vanishes from the statistics, so every entry must be something a
 * real browser never sends. A bot that slips through is only a slightly
 * inflated number.
 *
 * Detection is one pass over the User-Agent, cheapest first:
 *   1. empty User-Agent
 *   2. 'agents'   — substring (case-insensitive) => label
 *   3. 'pattern'  — one regex; a name found by the match is used as the label
 *   4. an http(s):// URL inside the User-Agent ("+https://example.com/bot")
 *   5. User-Agent that does not start with "Mozilla/" or "Opera/"
 *
 * A name ending in "bot" ("AhrefsBot", "MJ12bot", "GPTBot") is picked up by
 * the pattern, so it does not need an entry here. Entries below are for
 * bots whose name does not say so.
 */
return [

    'agents' => [

        // ── Uptime / status monitors ──────────────────────────────────────────
        // Specific names before the generic 'uptime' / 'monitor' fallbacks.
        'pulsetic'          => 'Pulsetic',
        'uptimerobot'       => 'UptimeRobot',
        'uptime-kuma'       => 'Uptime Kuma',
        'pingdom'           => 'Pingdom',
        'statuscake'        => 'StatusCake',
        'site24x7'          => 'Site24x7',
        'freshping'         => 'Freshping',
        'nodeping'          => 'NodePing',
        'hetrixtools'       => 'HetrixTools',
        'betterstack'       => 'Better Stack',
        'checkly'           => 'Checkly',
        'updown.io'         => 'updown.io',
        'newrelic'          => 'New Relic',
        'datadog'           => 'Datadog',
        'zabbix'            => 'Zabbix',
        'nagios'            => 'Nagios',
        'uptime'            => 'Uptime monitor',
        'monitor'           => 'Monitor',
        'healthcheck'       => 'Health check',
        'health-check'      => 'Health check',

        // ── Performance / SEO audit tools ─────────────────────────────────────
        'lighthouse'        => 'Lighthouse',
        'pagespeed'         => 'PageSpeed',
        'gtmetrix'          => 'GTmetrix',

        // ── AI assistants and agents whose name does not end in "bot" ─────────
        'chatgpt'           => 'ChatGPT',
        'claude-user'       => 'Claude-User',
        'claude-web'        => 'Claude-Web',
        'anthropic-ai'      => 'anthropic-ai',
        'perplexity'        => 'Perplexity',
        'meta-external'     => 'Meta-ExternalAgent',
        'cohere-ai'         => 'cohere-ai',
        'diffbot'           => 'Diffbot',

        // ── Link-preview fetchers ─────────────────────────────────────────────
        'facebookexternalhit' => 'Facebook',
        'embedly'           => 'Embedly',
        'skypeuripreview'   => 'Skype',

        // ── Search engines whose name does not end in "bot" ───────────────────
        'googleother'       => 'GoogleOther',
        'google-'           => 'Google',
        'mediapartners'     => 'Google AdSense',
        'feedfetcher'       => 'Feedfetcher',
        'yahoo! slurp'      => 'Yahoo Slurp',

        // ── HTTP clients and libraries ────────────────────────────────────────
        'curl/'             => 'curl',
        'wget/'             => 'Wget',
        'python-requests'   => 'python-requests',
        'python-urllib'     => 'python-urllib',
        'python-httpx'      => 'httpx',
        'aiohttp'           => 'aiohttp',
        'go-http-client'    => 'Go-http-client',
        'okhttp'            => 'OkHttp',
        'java/'             => 'Java',
        'apache-httpclient' => 'Apache-HttpClient',
        'libwww-perl'       => 'libwww-perl',
        'node-fetch'        => 'node-fetch',
        'axios/'            => 'axios',
        'undici'            => 'undici',
        'guzzlehttp'        => 'Guzzle',
        'postmanruntime'    => 'Postman',
        'insomnia'          => 'Insomnia',
        'httpie'            => 'HTTPie',
        'scrapy'            => 'Scrapy',

        // ── Headless / automated browsers ─────────────────────────────────────
        'headlesschrome'    => 'HeadlessChrome',
        'phantomjs'         => 'PhantomJS',
        'puppeteer'         => 'Puppeteer',
        'playwright'        => 'Playwright',
        'selenium'          => 'Selenium',
    ],

    // Names ending in "bot" ("Googlebot", "AhrefsBot", "GPTBot"), plus
    // "spider", "crawler" and "slurp". Group 1 is the bot's own name.
    //
    // (?<![a-z0-9._-]) starts the match only at the beginning of a word, so the
    // greedy [a-z0-9._-]* is tried once per word instead of once per character.
    // Without it a long run of letters in a hostile User-Agent backtracks
    // quadratically — over a second for 8 KB when PCRE's JIT is off.
    //
    // (?<!cu) keeps the Cubot phone brand ("CUBOT NOTE 7") out of it. Other
    // brands that end in "bot" can be excluded the same way, or a wrong
    // match removed with $firewall->bots->removePattern().
    'pattern' => '/(?<![a-z0-9._-])([a-z0-9._-]*(?:(?<!cu)bot|spider|crawler|slurp))\b/i',
];
