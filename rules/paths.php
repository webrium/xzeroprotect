<?php

/**
 * Default suspicious / blocked path patterns.
 * Each entry is matched as a case-insensitive substring of REQUEST_URI.
 * You can add/remove entries at runtime via PatternDetector::addPath().
 */
return [
    // Common CMS admin panels
    'wp-admin',
    'wp-login',
    'wp-config',
    'xmlrpc',
    'wordpress',

    // Other CMS
    'administrator',      // Joomla
    'typo3',
    'drupal',

    // Server/config file exposure
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

    // Extensions that do NOT exist in a modern routed app
    '.asp',
    '.aspx',
    '.jsp',
    '.cfm',
    '.cgi',
    '.php',          // Remove this if your app serves raw .php files!

    // Info / diagnostic exposure
    'phpinfo',
    'server-status',
    'server-info',

    // Other common scan targets
    'setup.php',
    'install.php',
    'readme.html',
    'license.txt',
    'changelog',
];
