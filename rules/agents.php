<?php

/**
 * Default blocked User-Agent substrings (case-insensitive).
 * Covers well-known scanners, exploit tools, and mass crawlers.
 */
return [
    // SQL injection / web vuln scanners
    'sqlmap',
    'sqlninja',
    'havij',

    // General vulnerability scanners
    'nikto',
    'nessus',
    'acunetix',
    'netsparker',
    'burpsuite',
    'openvas',
    'w3af',
    'skipfish',
    'vega',

    // Port / network scanners
    'masscan',
    'nmap',
    'zmap',
    'zgrab',

    // Directory / path brute-forcers
    'dirbuster',
    'dirb',
    'gobuster',
    'feroxbuster',
    'wfuzz',
    'ffuf',

    // Brute-force / credential tools
    'hydra',
    'medusa',
    'patator',

    // Exploit frameworks
    'metasploit',
    'msfpayload',

    // Known malicious/aggressive bots
    'massdeface',
    'blackwidow',
    'petalbot',   // aggressive crawler
    'dotbot',

    // Semrush / Ahrefs are legitimate, widely-used SEO audit tools, not
    // attack tools — they are NOT hard-blocked by default. They still pass
    // through normal rate limiting like any other unverified bot, so a
    // heavy site audit is throttled rather than let through unlimited.
    // Block them yourself if you don't want their traffic:
    //   $firewall->patterns->addAgent('semrushbot');
    //   $firewall->patterns->addAgent('ahrefsbot');

    // Low-level HTTP libraries — NOT included by default because they are
    // also used by legitimate API clients and automation tools.
    // Add them explicitly if your site does not expose a public API:
    //   $firewall->patterns->addAgent('curl/');
    //   $firewall->patterns->addAgent('wget/');
    //   $firewall->patterns->addAgent('python-requests');
    //   $firewall->patterns->addAgent('go-http-client');
    'libwww-perl',
    'lwp-trivial',
];