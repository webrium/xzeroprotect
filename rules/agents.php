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

    // Aggressive SEO crawlers — blocked by default.
    // Remove these if you rely on Semrush / Ahrefs data for your site:
    //   $firewall->patterns->removeAgent('semrushbot');
    //   $firewall->patterns->removeAgent('ahrefsbot');
    'semrushbot',
    'ahrefsbot',

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