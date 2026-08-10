<?php

/**
 * Default payload detection patterns (PCRE).
 *
 * Applied to GET params, the POST body, the raw request body, and cookies —
 * which on a normal site means the text your visitors type into comment
 * boxes and support tickets. A pattern here is read against prose.
 *
 * RULE OF THUMB
 * ─────────────
 * Every pattern MUST require syntax that prose does not contain. Ordinary
 * English is full of 'select … from', 'insert into', 'C#', '--', '# heading'
 * and links ending in .html; a pattern matching any of those blocks paying
 * customers. Word boundaries and anchors are not optional here.
 *
 * Patterns deliberately left out of the defaults because no precise form of
 * them exists — add them if your input is never prose:
 *   sqli_select   /\bSELECT\b.+\bFROM\b/i   matches "Select a plan from the list"
 *   sqli_insert   /\bINSERT\s+INTO\b/i      matches "we insert into the database"
 *   xss_eval      /\beval\s*\(/i            matches any article about JavaScript
 *   xss_expression, and bare 'javascript:' outside an attribute
 *
 * Input is percent-decoded until stable before matching, so double-encoded
 * payloads are seen in their decoded form.
 */
return [
    // ── SQL injection ──────────────────────────────────────────────────────
    // UNION [ALL] SELECT, tolerating comment padding: UNION/**/SELECT
    ['label' => 'sqli_union',     'pattern' => '/\bUNION\b[\s\/\*]*(\bALL\b[\s\/\*]*)?\bSELECT\b/i'],
    ['label' => 'sqli_drop',      'pattern' => '/\bDROP\s+(TABLE|DATABASE|SCHEMA)\b/i'],
    ['label' => 'sqli_sleep',     'pattern' => '/\bSLEEP\s*\(\s*\d+\s*\)/i'],
    ['label' => 'sqli_benchmark', 'pattern' => '/\bBENCHMARK\s*\(\s*\d/i'],
    // A tautology fed through a closing quote: ' OR 1=1, ' AND '1'='1
    ['label' => 'sqli_quote',     'pattern' => '/[\'"]\s*\b(OR|AND)\b\s+[\'"]?[\w\'"]+\s*(=|<|>|\bLIKE\b)/i'],
    // A comment terminator immediately after a closing quote or paren, or a
    // MySQL version-gated comment. Bare '--' and '#' are ordinary punctuation.
    ['label' => 'sqli_comment',   'pattern' => '/([\'"\)]\s*(--|#)|\/\*!\d)/'],

    // ── Cross-site scripting ───────────────────────────────────────────────
    ['label' => 'xss_script',     'pattern' => '/<\s*script[\s>\/]/i'],
    // Any inline event handler, but only inside a tag — so prose that merely
    // mentions "onerror=" is untouched while <svg><animate onbegin=…> is not.
    ['label' => 'xss_handler',    'pattern' => '/<[a-z][^>]{0,200}?\son[a-z]{2,15}\s*=/is'],
    // javascript:/vbscript: only where it can actually execute: as an
    // attribute value. "JavaScript: The Good Parts" is a book, not an attack.
    ['label' => 'xss_uri_scheme', 'pattern' => '/[a-z-]+\s*=\s*["\']?\s*(javascript|vbscript)\s*:/i'],
    ['label' => 'xss_svg_onload', 'pattern' => '/<\s*svg[^>]*\son[a-z]{2,15}\s*=/i'],

    // ── Path traversal ─────────────────────────────────────────────────────
    ['label' => 'traversal',      'pattern' => '/\.\.[\/\\\\]/'],
    ['label' => 'traversal_enc',  'pattern' => '/%2e%2e(%2f|%5c|\/|\\\\)/i'],

    // ── PHP code injection ─────────────────────────────────────────────────
    ['label' => 'php_exec',       'pattern' => '/\b(system|exec|passthru|popen|proc_open|shell_exec)\s*\(\s*[\$\'"]/i'],
    ['label' => 'php_eval',       'pattern' => '/\beval\s*\(\s*(base64_decode|gzinflate|str_rot13|\$_)/i'],
    ['label' => 'php_assert',     'pattern' => '/\bassert\s*\(\s*[\$\'"]/i'],
    ['label' => 'php_wrapper',    'pattern' => '/\bphp:\/\/(input|filter|data)/i'],

    // ── File inclusion ─────────────────────────────────────────────────────
    ['label' => 'lfi',            'pattern' => '/(\/etc\/(passwd|shadow)\b|\/proc\/self\/environ\b)/i'],
    // A remote script pulled in as a parameter value. Extensions are anchored
    // to the end of the URL, and .html is excluded — linking to a web page is
    // not an attack.
    ['label' => 'rfi',            'pattern' => '/\b(https?|ftp):\/\/[^\s"\'<>]+\.(php\d?|phtml|txt)(\?|#|&|$)/i'],

    // ── Command injection ──────────────────────────────────────────────────
    // A shell separator, a command, and an argument. Requiring the argument
    // keeps "tags=music; categories=rock" and "send your ID; identity check"
    // out of the log.
    ['label' => 'cmd_injection',  'pattern' => '/[;|&`]\s*(cat|ls|wget|curl|nc|bash|sh|python|perl|whoami|uname)\s+[\/\-\w]/i'],
    ['label' => 'cmd_substitute', 'pattern' => '/\$\(\s*(cat|ls|id|whoami|uname|curl|wget)\b/i'],
];
