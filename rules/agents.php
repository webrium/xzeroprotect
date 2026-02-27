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
    'petalbot',    // aggressive crawler
    'semrushbot',  // aggressive SEO crawler — remove if you want Semrush data
    'ahrefsbot',   // remove if you want Ahrefs data
    'dotbot',

    // Generic bad-bot patterns
    'python-requests',
    'go-http-client',
    'curl/',        // might want to keep for API—remove if your API uses curl
    'libwww-perl',
    'lwp-trivial',
    'wget/',
];
