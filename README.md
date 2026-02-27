<div align="center">

<br/>

```
██╗  ██╗███████╗███████╗██████╗  ██████╗ ██████╗ ██████╗  ██████╗ ████████╗███████╗ ██████╗████████╗
╚██╗██╔╝╚══███╔╝██╔════╝██╔══██╗██╔═══██╗██╔══██╗██╔══██╗██╔═══██╗╚══██╔══╝██╔════╝██╔════╝╚══██╔══╝
 ╚███╔╝   ███╔╝ █████╗  ██████╔╝██║   ██║██████╔╝██████╔╝██║   ██║   ██║   █████╗  ██║        ██║   
 ██╔██╗  ███╔╝  ██╔══╝  ██╔══██╗██║   ██║██╔═══╝ ██╔══██╗██║   ██║   ██║   ██╔══╝  ██║        ██║   
██╔╝ ██╗███████╗███████╗██║  ██║╚██████╔╝██║      ██║  ██║╚██████╔╝   ██║   ███████╗╚██████╗   ██║   
╚═╝  ╚═╝╚══════╝╚══════╝╚═╝  ╚═╝ ╚═════╝ ╚═╝     ╚═╝  ╚═╝ ╚═════╝    ╚═╝   ╚══════╝ ╚═════╝   ╚═╝   
```

**A lightweight, file-based PHP firewall for the modern web.**  
No database. No external services. No compromises.

<br/>

[![PHP](https://img.shields.io/badge/PHP-%3E%3D%208.0-8892BF?style=flat-square&logo=php&logoColor=white)](https://php.net)
[![Composer](https://img.shields.io/badge/Composer-webrium%2Fxzeroprotect-885630?style=flat-square&logo=composer&logoColor=white)](https://packagist.org/packages/webrium/xzeroprotect)
[![License](https://img.shields.io/badge/License-MIT-22c55e?style=flat-square)](LICENSE)
[![Zero Dependencies](https://img.shields.io/badge/Dependencies-Zero-f59e0b?style=flat-square)]()

<br/>

</div>

---

## Why xZeroProtect?

Every day, bots crawl your application looking for exposed `.env` files, WordPress admin panels, SQL injection vectors, and known CVEs — even if you're not running WordPress. xZeroProtect stops them at the PHP layer with zero external dependencies, no database connection, and a clean API you can tune in minutes.

- **File-based** — everything stored on disk; no MySQL, Redis, or memcached required
- **Zero dependencies** — pure PHP 8.0+, nothing else
- **Composable** — enable, disable, or extend every detection module independently
- **Learning mode** — log threats without blocking, perfect for tuning before going live
- **Apache-aware** — optionally write permanent bans into `.htaccess` so Apache rejects them before PHP even starts

---

## Installation

```bash
composer require webrium/xzeroprotect
```

---

## Quick Start

Add these two lines at the very top of your `index.php` or bootstrap file:

```php
<?php
require 'vendor/autoload.php';

use Webrium\XZeroProtect\XZeroProtect;

XZeroProtect::init()->run();
```

That's it. Default rules are active immediately.

---

## Configuration

Every option has a sensible default. Override only what you need:

```php
$firewall = XZeroProtect::init([

    // 'production' → block & log  |  'learning' → log only  |  'off' → disabled
    'mode'         => 'production',

    // Where ban files, rate data, and logs are stored
    'storage_path' => __DIR__ . '/storage/firewall',

    // --- Rate limiting ---
    'rate_limit' => [
        'enabled'      => true,
        'max_requests' => 60,   // requests per window
        'per_seconds'  => 60,   // window size in seconds
    ],

    // --- Automatic banning ---
    'auto_ban' => [
        'enabled'              => true,
        'violations_threshold' => 5,      // violations before a ban is issued
        'ban_duration'         => 86400,  // ban length in seconds (24 h)
        'permanent_after_bans' => 3,      // escalate to permanent after N bans
    ],

    // --- Apache integration ---
    'apache_blocking' => false,
    'htaccess_path'   => __DIR__ . '/.htaccess',

    // --- Always-allow list ---
    'whitelist' => [
        'ips'   => ['127.0.0.1', '10.0.0.0/8'],
        'paths' => ['/health', '/ping'],
    ],

    // --- Response sent to blocked clients ---
    'block_response' => [
        'code'    => 403,
        'message' => 'Access Denied',
    ],

    // --- Toggle individual detection modules ---
    'checks' => [
        'rate_limit'   => true,
        'blocked_path' => true,
        'user_agent'   => true,
        'payload'      => true,
        'custom_rules' => true,
    ],

    // --- Log settings ---
    'log' => [
        'enabled'       => true,
        'max_file_size' => 10,   // MB — auto-rotated when exceeded
        'keep_days'     => 30,
    ],

]);

$firewall->run();
```

---

## Detection Modules

### Path Detection

Blocks requests targeting sensitive or non-existent paths. Because a modern routed PHP app has no `.php` files in the URL, you can add that pattern to immediately reject the flood of `index.php?id=` scanner probes.

```php
// Add individual patterns
$firewall->patterns->addPath('.php');
$firewall->patterns->addPath('/control-panel');

// Add many at once
$firewall->patterns->addPaths(['.asp', '.jsp', '/backup', '/staging']);

// Remove a default pattern you want to allow
$firewall->patterns->removePath('xmlrpc');
```

<details>
<summary>View all default blocked paths</summary>

| Category | Patterns |
|----------|----------|
| CMS panels | `wp-admin`, `wp-login`, `wp-config`, `xmlrpc`, `administrator`, `typo3` |
| Config exposure | `.env`, `.git`, `.svn`, `.htaccess`, `.htpasswd`, `web.config` |
| DB tools | `phpmyadmin`, `pma`, `adminer`, `dbadmin` |
| Dangerous files | `.sql`, `.bak`, `.backup`, `.old`, `dump.sql` |
| Path traversal | `../`, `..%2f`, `%2e%2e` |
| Web shells | `shell.php`, `c99.php`, `r57.php`, `webshell` |
| Script extensions | `.asp`, `.aspx`, `.jsp`, `.cfm`, `.cgi`, `.php` |
| Info disclosure | `phpinfo`, `server-status`, `server-info` |
| Install artifacts | `setup.php`, `install.php`, `readme.html` |

</details>

---

### User-Agent Detection

Identifies and blocks known scanner, brute-force, and exploit tool signatures. Empty User-Agent strings are treated as suspicious by default.

```php
$firewall->patterns->addAgent('custom-bad-bot');
$firewall->patterns->removeAgent('curl'); // allow curl if your API clients use it
```

<details>
<summary>View default blocked agents</summary>

`sqlmap` · `nikto` · `nessus` · `acunetix` · `netsparker` · `masscan` · `nmap` · `zgrab` · `dirbuster` · `gobuster` · `feroxbuster` · `wfuzz` · `ffuf` · `hydra` · `metasploit` · `python-requests` · `go-http-client` · `libwww-perl` · `wget` · and more

</details>

---

### Payload Detection

Scans GET parameters, POST body, raw input, and cookies for attack signatures using compiled regular expressions.

```php
// Add a custom pattern
$firewall->patterns->addPayload('/CUSTOM_EXPLOIT/i', 'my_label');

// Remove a built-in pattern
$firewall->patterns->removePayload('sqli_union');
```

<details>
<summary>View default payload rules</summary>

| Label | Detects |
|-------|---------|
| `sqli_union` | `UNION [ALL] SELECT` |
| `sqli_select` | `SELECT ... FROM` |
| `sqli_drop` | `DROP TABLE/DATABASE` |
| `sqli_sleep` | `SLEEP(n)` time-based blind |
| `sqli_benchmark` | `BENCHMARK(...)` |
| `sqli_comment` | `--`, `#`, `/* */` injection comments |
| `xss_script` | `<script` tags |
| `xss_onerror` | Inline event handlers (`onerror=`, `onclick=`, ...) |
| `xss_javascript` | `javascript:` protocol |
| `traversal` | `../` path traversal |
| `php_exec` | `system()`, `exec()`, `shell_exec()`, ... |
| `php_eval` | `eval(base64_decode(...))` |
| `lfi` | `/etc/passwd`, `/etc/shadow` |
| `rfi` | Remote file inclusion URLs |
| `cmd_injection` | Shell metacharacters + commands |

</details>

---

### Rate Limiting

Sliding-window counter stored per-IP on disk. No Redis required.

```php
$firewall = XZeroProtect::init([
    'rate_limit' => [
        'max_requests' => 30,
        'per_seconds'  => 10,
    ],
]);
```

---

## IP Management

```php
// Temporary ban (24 h default)
$firewall->ip->ban('1.2.3.4');
$firewall->ip->ban('1.2.3.4', reason: 'manual review', duration: 3600);

// Permanent ban
$firewall->ip->banPermanent('1.2.3.4', reason: 'confirmed attacker');

// Remove a ban
$firewall->ip->unban('1.2.3.4');

// Inspect
$firewall->ip->isBanned('1.2.3.4');    // bool
$firewall->ip->getBanInfo('1.2.3.4');  // array|null  { ip, reason, banned_at, expires, bans_count }
$firewall->ip->getAllBans();            // array of all active bans

// Whitelist — supports exact IPs and CIDR notation (IPv4 & IPv6)
$firewall->ip->whitelist('10.0.0.0/8');
$firewall->ip->whitelist('2001:db8::/32');
```

---

## Custom Rules

Register your own logic as first-class firewall rules with full access to the request object.

```php
use Webrium\XZeroProtect\RuleResult;

// Block requests with a .php extension (for fully-routed apps)
$firewall->rules->add('no-php-extension', function ($request) {
    if (str_ends_with($request->path(), '.php')) {
        return RuleResult::block('PHP extension not valid on this server');
    }
    return RuleResult::pass();
});

// Log suspicious POST requests without logging a violation
$firewall->rules->add('post-no-referer', function ($request) {
    if ($request->method === 'POST' && empty($request->referer)) {
        return RuleResult::log('POST without Referer header');
    }
    return RuleResult::pass();
}, priority: 10);  // lower = runs first

// Manage rules at runtime
$firewall->rules->disable('no-php-extension');
$firewall->rules->enable('no-php-extension');
$firewall->rules->remove('no-php-extension');
```

**`RuleResult` options:**

| Method | Effect |
|--------|--------|
| `RuleResult::pass()` | Allow the request, continue checking |
| `RuleResult::block(reason: '...')` | Block immediately and log |
| `RuleResult::log(reason: '...')` | Log without blocking |

---

## Apache Integration

When `apache_blocking` is enabled, permanently banned IPs are written to `.htaccess`. Apache drops those connections before PHP starts — zero PHP overhead for known bad actors.

```php
$firewall = XZeroProtect::init([
    'apache_blocking' => true,
    'htaccess_path'   => __DIR__ . '/.htaccess',
]);

// Sync all current permanent bans to .htaccess
$firewall->apache->sync(array_keys($firewall->ip->getAllBans()));

// Block/unblock a single IP in .htaccess
$firewall->apache->block('5.6.7.8');
$firewall->apache->unblock('5.6.7.8');
```

Generated `.htaccess` block:

```apache
# xZeroProtect:start
# Auto-generated by xZeroProtect — do not edit this block manually
<RequireAll>
    Require all granted
    Require not ip 1.2.3.4
    Require not ip 5.6.7.8
</RequireAll>
# xZeroProtect:end
```

---

## Logging

```php
// Read the most recent attack entries (newest first)
$logs = $firewall->logger->recent(limit: 100);

// Clean up rotated backup log files older than retention period
$firewall->logger->cleanup();
```

Log entries are plain-text, one per line:

```
2024-11-15 14:32:01 | ip=185.220.101.5 | type=sqli_union | uri=/search?q=1+UNION+SELECT | reason=Payload match: sqli_union | ua=sqlmap/1.7
```

---

## Disabling Individual Checks

```php
// At init time
XZeroProtect::init([
    'checks' => [
        'user_agent' => false,  // disable UA checking for this app
    ],
]);

// Or at runtime
$firewall->disableCheck('user_agent');
$firewall->enableCheck('user_agent');
```

Available check keys: `rate_limit` · `blocked_path` · `user_agent` · `payload` · `custom_rules`

---

## Learning Mode

Deploy in learning mode first. All attacks are logged but nothing is blocked. Review the logs, tune your rules, then switch to production.

```php
// During tuning
XZeroProtect::init(['mode' => 'learning'])->run();

// Once satisfied
XZeroProtect::init(['mode' => 'production'])->run();
```

---

## Architecture

```
xzeroprotect/
├── src/
│   ├── XZeroProtect.php      Main class & orchestrator
│   ├── Request.php           HTTP request context
│   ├── Storage.php           File-based persistence (bans, rate, violations, logs)
│   ├── IPManager.php         Ban/whitelist management with CIDR support
│   ├── PatternDetector.php   Path, User-Agent, and payload matching
│   ├── RateLimiter.php       Sliding-window rate limiter
│   ├── RuleEngine.php        Custom rule registration & execution
│   ├── ApacheBlocker.php     .htaccess read/write
│   └── Logger.php            Attack logging with rotation
├── config/
│   └── config.php            Default configuration
├── rules/
│   ├── paths.php             Default blocked path patterns
│   ├── agents.php            Default blocked User-Agent signatures
│   └── payloads.php          Default attack payload patterns (PCRE)
└── tests/
    └── XZeroProtectTest.php  PHPUnit test suite
```

---

## Requirements

- PHP **8.0** or higher
- Write permission on the storage directory

---

## License

Released under the [MIT License](LICENSE).  
Built by [Webrium](https://github.com/webrium).