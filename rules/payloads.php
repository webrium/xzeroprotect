<?php

/**
 * Default payload detection patterns (PCRE regex).
 * Applied to GET params, POST body (as raw string), and cookies.
 *
 * Each entry: ['label' => string, 'pattern' => string]
 */
return [
    // SQL Injection
    ['label' => 'sqli_union',    'pattern' => '/UNION\s+(ALL\s+)?SELECT/i'],
    ['label' => 'sqli_select',   'pattern' => '/SELECT\s+.+\s+FROM\s+/i'],
    ['label' => 'sqli_insert',   'pattern' => '/INSERT\s+INTO\s+/i'],
    ['label' => 'sqli_drop',     'pattern' => '/DROP\s+(TABLE|DATABASE|SCHEMA)\s+/i'],
    ['label' => 'sqli_sleep',    'pattern' => '/SLEEP\s*\(\s*\d+\s*\)/i'],
    ['label' => 'sqli_benchmark','pattern' => '/BENCHMARK\s*\(/i'],
    ['label' => 'sqli_comment',  'pattern' => '/(\-\-\s|#\s|\/\*.*\*\/)/'],
    ['label' => 'sqli_quote',    'pattern' => "/'\s*(OR|AND)\s+'?\d/i"],

    // XSS
    ['label' => 'xss_script',    'pattern' => '/<script[\s>]/i'],
    ['label' => 'xss_onerror',   'pattern' => '/on(error|load|click|mouseover|focus|blur)\s*=/i'],
    ['label' => 'xss_javascript','pattern' => '/javascript\s*:/i'],
    ['label' => 'xss_vbscript', 'pattern' => '/vbscript\s*:/i'],
    ['label' => 'xss_eval',      'pattern' => '/eval\s*\(/i'],
    ['label' => 'xss_expression','pattern' => '/expression\s*\(/i'],

    // Path Traversal
    ['label' => 'traversal',     'pattern' => '/\.\.(\/|\\\\)/'],
    ['label' => 'traversal_enc', 'pattern' => '/%2e%2e(%2f|%5c)/i'],

    // PHP-specific code injection
    ['label' => 'php_exec',      'pattern' => '/(system|exec|passthru|popen|proc_open|shell_exec)\s*\(/i'],
    ['label' => 'php_eval',      'pattern' => '/eval\s*\(\s*base64_decode/i'],
    ['label' => 'php_assert',    'pattern' => '/assert\s*\(\s*[\$\'\"]/i'],

    // File inclusion
    ['label' => 'lfi',           'pattern' => '/(\/etc\/passwd|\/etc\/shadow|\/proc\/self\/environ)/i'],
    ['label' => 'rfi',           'pattern' => '/(https?|ftp):\/\/.+\.(php|txt|htm)/i'],

    // Command injection
    ['label' => 'cmd_injection', 'pattern' => '/(\||;|`|&&|\$\()\s*(ls|cat|wget|curl|id|whoami|uname)/i'],
];
