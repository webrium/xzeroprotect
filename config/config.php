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
    */
    'auto_ban' => [
        'enabled'              => true,
        'violations_threshold' => 5,       // violations before ban
        'ban_duration'         => 86400,   // seconds (24h), 0 = permanent
        'permanent_after_bans' => 3,       // X temp bans → permanent
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
    | Checks — enable/disable individual detection modules
    |--------------------------------------------------------------------------
    */
    'checks' => [
        'rate_limit'   => true,
        'blocked_path' => true,
        'user_agent'   => true,
        'payload'      => true,
        'custom_rules' => true,
    ],

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
    | Logging
    |--------------------------------------------------------------------------
    */
    'log' => [
        'enabled'        => true,
        'max_file_size'  => 10,   // MB — rotate when exceeded
        'keep_days'      => 30,
    ],

];
