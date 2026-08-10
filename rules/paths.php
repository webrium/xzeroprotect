<?php

/**
 * Default blocked path patterns.
 *
 * MATCHING (see PatternDetector::isSuspiciousPath)
 * ────────────────────────────────────────────────
 * Patterns are matched per path segment, not as a substring of the URI, and
 * the query string is never examined. So 'wp-admin' matches '/wp-admin/' and
 * '/wp-admin/setup-config.php' but not '/posts/how-i-left-wp-admin-behind',
 * and 'phpinfo' matches '/phpinfo.php' but not '/posts/reading-phpinfo-output'.
 *
 *   'name'      matches a whole segment, with or without a file extension
 *   '.ext'      matches the end of a segment  ('.env' also matches '.env.bak')
 *   '../', '%…' raw signature, matched anywhere — never a legitimate segment
 *
 * CHOOSING A PATTERN
 * ──────────────────
 * A blocked path costs a real visitor their session and, with auto_ban on,
 * a day of access. Only add a pattern that can never be a page on a normal
 * site. Ordinary English words are not safe entries even as whole segments:
 * 'administrator' is a Joomla panel but also a plausible documentation page,
 * so it is left out. Add it yourself if you actually run Joomla:
 *   $firewall->patterns->addPath('administrator');
 */
return [
    // WordPress
    'wp-admin',
    'wp-login',
    'wp-config',
    'xmlrpc',

    // Other CMS back ends
    'typo3',

    // Server / config file exposure
    '.env',
    '.git',
    '.svn',
    '.htaccess',
    '.htpasswd',
    'web.config',

    // Database tools
    'phpmyadmin',
    'pma',
    'adminer',
    'dbadmin',

    // Backup / sensitive file extensions
    '.sql',
    '.bak',
    '.backup',
    '.old',
    '.orig',
    'config.bak',
    'dump.sql',

    // Path traversal
    '../',
    '..%2f',
    '%2e%2e',

    // Shell / script exposure
    'shell.php',
    'c99.php',
    'r57.php',
    'webshell',
    'eval-stdin.php',   // PHPUnit RCE probe (CVE-2017-9841)

    // Extensions that do NOT exist in a modern routed app
    '.asp',
    '.aspx',
    '.jsp',
    '.cfm',
    '.cgi',

    // '.php' is intentionally NOT blocked by default.
    // If your app uses modern routing and serves no raw PHP files, add it:
    //   $firewall->patterns->addPath('.php');

    // Info / diagnostic exposure
    'phpinfo',
    'server-status',
    'server-info',

    // Other common scan targets
    'setup.php',
    'install.php',
    'readme.html',
    'license.txt',
    'changelog.txt',    // version fingerprinting; '/changelog' is a real page
];
