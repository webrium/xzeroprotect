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

> **Note:** `init()` stores the instance internally. You can retrieve it from anywhere in your application using `XZeroProtect::getInstance()` — no need to pass `$firewall` around.

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
        'violations_threshold' => 10,     // violations within violation_window before a ban
        'violation_window'     => 3600,   // rolling window (seconds) violations are counted in
        'ban_duration'         => 86400,  // ban length in seconds (24 h)
        'permanent_after_bans' => 3,      // escalate to permanent after N bans
    ],

    // --- Apache integration ---
    'apache_blocking' => false,
    'htaccess_path'   => __DIR__ . '/.htaccess',

    // --- Reverse proxies / CDNs (e.g. Cloudflare, Nginx, load balancers) ---
    // Leave empty to always use REMOTE_ADDR (safest if the server is
    // reachable directly). Add proxy IPs/CIDRs to read the real client IP
    // from CF-Connecting-IP / True-Client-IP / X-Real-IP / X-Forwarded-For
    // when the request comes from one of these proxies. Use ['*'] to trust
    // these headers regardless of REMOTE_ADDR (only if the server is NOT
    // directly reachable).
    'trusted_proxies' => [],

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
        'crawler_check' => true,   // exempt verified crawlers from all checks
        'rate_limit'    => true,
        'blocked_path'  => true,
        'user_agent'    => true,
        'payload'       => true,
        'custom_rules'  => true,
    ],

    // --- Log settings ---
    'log' => [
        'enabled'       => true,
        'max_file_size' => 10,   // MB — auto-rotated when exceeded
        'keep_days'     => 30,
        'auto_cleanup'  => true, // sweep expired .bak files on real traffic, no cron needed
    ],

]);

$firewall->run();
```

---

## Detection Modules

> ### Accuracy comes first
>
> A false positive costs more than a false negative. A missed probe gets a `404` from your router; a wrongly blocked visitor gets a `403`, and with `auto_ban` on, loses access for a day — on a carrier NAT, so do thousands of other people.
>
> Two rules follow from that, and they are enforced by `tests/DetectionAccuracyTest.php`:
>
> - **Paths are matched per segment, and the query string is never examined.** `wp-admin` matches `/wp-admin/setup-config.php`, not `/posts/how-i-left-wp-admin-behind`. `/search?q=wordpress` is a site search, not an attack.
> - **Payload patterns must require syntax that prose does not contain.** These run against comment boxes and support tickets. `SELECT … FROM` is also "Select a plan from the list", `#` is also a markdown heading and the C# language, and a link ending in `.html` is a link.
>
> Ordinary English words are not safe pattern entries even as whole segments, so `administrator`, `wordpress`, `drupal` and bare `changelog` are **not** in the defaults. Add them if they cannot be pages on your site.

### Path Detection

Blocks requests targeting sensitive or non-existent paths. Because a modern routed PHP app has no `.php` files in the URL, you can add that pattern to immediately reject the flood of `index.php?id=` scanner probes.

Patterns are matched against path segments:

| Pattern form | Matches | Does not match |
|---|---|---|
| `wp-admin` | `/wp-admin/`, `/wp-admin/x.php`, `/blog/wp-admin` | `/posts/leaving-wp-admin` |
| `phpinfo` | `/phpinfo.php` | `/posts/reading-phpinfo-output` |
| `.env` | `/.env`, `/config/.env`, `/.env.bak` | `/posts/dotenv-guide` |
| `../`, `%2e%2e` | anywhere in the URI — always hostile | — |

Percent-encoding is decoded until stable first, so `/wp-admin%2Fsetup.php` and `..%252f..%252f` are matched in their decoded form.

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
| Script extensions | `.asp`, `.aspx`, `.jsp`, `.cfm`, `.cgi` |
| Info disclosure | `phpinfo`, `server-status`, `server-info` |
| Install artifacts | `setup.php`, `install.php`, `readme.html` |

> **Note:** `.php` is **not** blocked by default to avoid false positives on applications that serve raw PHP files. Add it explicitly if your app uses modern routing: `$firewall->patterns->addPath('.php')`

</details>

---

### User-Agent Detection

Identifies and blocks known scanner, brute-force, and exploit tool signatures.

An **empty User-Agent is allowed by default**. Feed readers, uptime probes, and some proxies send none; an absent UA is unusual, not hostile, and counting it as a violation fed `auto_ban` with legitimate clients. Enable it only if every client of your app is known to send one:

```php
XZeroProtect::init(['empty_user_agent_suspicious' => true]);
```

```php
$firewall->patterns->addAgent('custom-bad-bot');
$firewall->patterns->removeAgent('curl'); // allow curl if your API clients use it
```

<details>
<summary>View default blocked agents</summary>

`sqlmap` · `nikto` · `nessus` · `acunetix` · `netsparker` · `masscan` · `nmap` · `zgrab` · `dirbuster` · `gobuster` · `feroxbuster` · `wfuzz` · `ffuf` · `hydra` · `metasploit` · `semrushbot` · `ahrefsbot` · `libwww-perl` · and more

> **Note:** `curl`, `wget`, `python-requests`, and `go-http-client` are **not** blocked by default because they are also used by legitimate API clients. Add them explicitly if needed:
> ```php
> $firewall->patterns->addAgent('curl/');
> $firewall->patterns->addAgent('wget/');
> $firewall->patterns->addAgent('python-requests');
> $firewall->patterns->addAgent('go-http-client');
> ```

</details>

---

### Payload Detection

Scans GET parameters, POST body, raw input, and cookies for attack signatures using compiled regular expressions. Input is percent-decoded until stable before matching, so double-encoded payloads are seen in their decoded form.

**Known limitation:** HTML-entity obfuscation inside an attribute (`<body background="javascript&colon;">`) is not detected. Decoding entities before matching would flag any prose that merely quotes HTML, which costs more than this bypass does — output escaping, not the firewall, is the defence against stored XSS.

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

Every request past the limit is still blocked — that part is unconditional. But a real page load can fire far more requests than the limit in one burst: a dashboard's async widgets, a flaky connection retrying, a few open tabs. A single such burst is not an attack, so it is recorded as **at most one** `auto_ban` violation per rate-limit window, no matter how many individual requests overflowed it. A client that keeps exceeding the limit across many separate windows — the thing `auto_ban` exists to catch — still racks up one violation per window and is banned once `violations_threshold` is reached.

Violations also decay: only those within the rolling `violation_window` (default 1h) count toward the threshold, so an old, one-off blip does not sit on a client's record forever.

---

## Crawler Detection

Trusted web crawlers (Googlebot, Bingbot, and others) are identified and exempted from all firewall checks — including rate limiting and auto-ban. This prevents legitimate bots from being accidentally blocked.

For crawlers like Googlebot and Bingbot, identity is confirmed via **double-DNS verification** before granting trust:

1. Resolve the visitor IP to a hostname via reverse DNS
2. Confirm the hostname ends with the expected suffix (e.g. `.googlebot.com`)
3. Re-resolve that hostname back to an IP
4. Confirm the re-resolved IP matches the original visitor IP

This is the verification method recommended by Google and Bing in their official documentation. Anyone can fake a User-Agent — DNS cannot be faked.

Social crawlers (Twitterbot, LinkedInBot, Slackbot, etc.) are trusted by User-Agent only, as they do not publish verifiable IP ranges or rDNS suffixes.

### Verification caching

Double-DNS verification costs two blocking network round-trips — measured at **~770 ms** for a real Googlebot hit, during which a PHP worker does nothing but wait. Under a heavy crawl that adds up to hours of blocked workers, and a flood of spoofed `Googlebot` User-Agents becomes a cheap way to pin every worker you have.

Verdicts are therefore cached on disk, keyed by IP + expected rDNS suffix:

```
request 1:  770.74 ms   ← resolved
request 2:    0.06 ms   ← cached
request 3:    0.01 ms
```

Failed verifications get the shorter `negative_ttl`, so a transient resolver outage cannot lock a legitimate crawler out for a full day, while repeated spoofed User-Agents are still absorbed.

```php
$firewall = XZeroProtect::init([
    'crawler_cache' => [
        'enabled'      => true,
        'ttl'          => 86400,   // verified crawler (24h)
        'negative_ttl' => 3600,    // failed verification (1h)
    ],
]);

$firewall->crawlers->clearCache();        // after editing the crawler list
$firewall->crawlers->cleanupCache();      // drop expired entries — safe for cron
$firewall->crawlers->isCachePersistent(); // bool
```

A cache that cannot be written degrades into extra DNS lookups, never into a failed request.

```php
// Add a custom trusted crawler
$firewall->crawlers->addCrawler(
    name: 'MyCrawler',
    uaContains: 'mycrawlerbot',
    verifyRdns: false
);

// Remove a crawler from the trusted list
$firewall->crawlers->removeCrawler('Googlebot');

// Disable crawler detection entirely
$firewall->disableCheck('crawler_check');
```

<details>
<summary>View default trusted crawlers</summary>

| Crawler | UA contains | DNS verified |
|---------|-------------|:------------:|
| Googlebot | `googlebot` | ✅ `.googlebot.com` |
| Google Other | `google` | ✅ `.google.com` |
| Bingbot | `bingbot` | ✅ `.search.msn.com` |
| Yahoo Slurp | `yahoo! slurp` | ✅ `.crawl.yahoo.net` |
| DuckDuckBot | `duckduckbot` | — |
| Yandex | `yandexbot` | ✅ `.yandex.com` |
| Baidu | `baiduspider` | ✅ `.baidu.com` |
| Applebot | `applebot` | ✅ `.applebot.apple.com` |
| Facebook | `facebookexternalhit` | ✅ `.facebook.com` |
| Twitterbot | `twitterbot` | — |
| LinkedInBot | `linkedinbot` | — |
| WhatsApp | `whatsapp` | — |
| Telegram | `telegrambot` | — |
| Slackbot | `slackbot` | — |
| Discordbot | `discordbot` | — |
| Uptimerobot | `uptimerobot` | — |
| Pingdom | `pingdom` | — |

</details>

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

// Page further back without loading the whole file
$logs = $firewall->logger->recent(limit: 100, offset: 100);

// Total lines currently in the active log — for building pagination
// without reading (or parsing) every line
$total = $firewall->logger->total();

// Force a cleanup of rotated backups older than keep_days right now
$firewall->logger->cleanup();
```

`recent()` reads backward from the end of the log file in chunks (like
`tail -n`), so cost scales with how far back a page reaches, not with total
file size — reading the newest 100 lines out of a 10MB log doesn't load the
10MB.

Rotated `.bak` backups (see `max_file_size` above) are swept once they're
older than `keep_days`. This runs on its own — no system cron needed:
`log.auto_cleanup` (default `true`) checks on real log-write traffic,
gated to at most once a day, so it adds no meaningful cost to the
(already rare) attack-logging path. Set it to `false` only if you already
run your own cleanup (cron, logrotate, ...).

### Accessing the firewall from outside bootstrap

Because `init()` stores the instance as a singleton, you can retrieve it from any controller, admin panel, or CLI script without passing `$firewall` as a variable:

```php
use Webrium\XZeroProtect\XZeroProtect;

// In bootstrap / index.php
XZeroProtect::init()->run();

// ---

// In any other file (e.g. admin panel, dashboard controller)
$firewall = XZeroProtect::getInstance();

$logs    = $firewall->logger->recent(limit: 100);
$bans    = $firewall->ip->getAllBans();
$isBanned = $firewall->ip->isBanned('1.2.3.4');
```

If `getInstance()` is called before `init()`, it throws a clear `RuntimeException`:

```
xZeroProtect has not been initialized. Call XZeroProtect::init() first.
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

Available check keys: `crawler_check` · `rate_limit` · `blocked_path` · `user_agent` · `payload` · `custom_rules`

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

## Visitor Tracking

After all firewall checks pass, xZeroProtect can record verified real visits — bots, scanners, and suspicious requests are already filtered out before this runs.

Tracking is **opt-in** and **disabled by default**. Enable it by passing a closure to `enableTracking()` before calling `run()`. The closure receives a `VisitInfo` object; how you store the data is entirely up to you.

```php
use Webrium\XZeroProtect\XZeroProtect;
use Webrium\XZeroProtect\VisitInfo;

$firewall = XZeroProtect::init();

$firewall->enableTracking(function (VisitInfo $visit) {
    // Store in your database however you like
    $pdo->prepare("
        INSERT INTO visits
            (ip, path, method, referer, user_agent,
             browser, browser_version, os, os_version,
             device_type, fingerprint, visited_at)
        VALUES
            (:ip, :path, :method, :referer, :user_agent,
             :browser, :browser_ver, :os, :os_ver,
             :device_type, :fingerprint, :visited_at)
    ")->execute([
        ':ip'          => $visit->ip,
        ':path'        => $visit->path,
        ':method'      => $visit->method,
        ':referer'     => $visit->referer,
        ':user_agent'  => $visit->userAgent,
        ':browser'     => $visit->device->browser,
        ':browser_ver' => $visit->device->browserVersion,
        ':os'          => $visit->device->os,
        ':os_ver'      => $visit->device->osVersion,
        ':device_type' => $visit->device->type,
        ':fingerprint' => $visit->fingerprint,
        ':visited_at'  => $visit->date(),
    ]);
});

$firewall->run();
```

### VisitInfo properties

| Property | Type | Description |
|----------|------|-------------|
| `$visit->ip` | `string` | Visitor IP address |
| `$visit->uri` | `string` | Full URI including query string |
| `$visit->path` | `string` | URI path without query string |
| `$visit->method` | `string` | HTTP method (`GET`, `POST`, ...) |
| `$visit->userAgent` | `string` | Raw User-Agent header |
| `$visit->referer` | `string` | HTTP Referer header |
| `$visit->timestamp` | `int` | Unix timestamp |
| `$visit->fingerprint` | `string` | SHA-256 unique visitor identifier (see below) |
| `$visit->device` | `DeviceInfo` | Parsed browser, OS, and device type |
| `$visit->date()` | `string` | Formatted timestamp — default `Y-m-d H:i:s` |
| `$visit->toArray()` | `array` | All fields as a flat array, ready for DB insert |

### DeviceInfo properties

Accessible via `$visit->device`:

| Property | Type | Example |
|----------|------|---------|
| `->browser` | `string` | `Chrome`, `Firefox`, `Safari`, `Edge`, `Opera` |
| `->browserVersion` | `string` | `124.0.0.0` |
| `->os` | `string` | `Windows`, `macOS`, `Android`, `iOS`, `Linux` |
| `->osVersion` | `string` | `10/11`, `17.0`, `13` |
| `->type` | `string` | `desktop`, `mobile`, `tablet` |
| `->isDesktop` | `bool` | `true` / `false` |
| `->isMobile` | `bool` | `true` / `false` |
| `->isTablet` | `bool` | `true` / `false` |

### Unique visitor fingerprinting

`$visit->fingerprint` is a **SHA-256 hash** of the visitor's IP, User-Agent, and the current date. This means:

- The same visitor on the same day always gets the **same fingerprint** — useful for deduplicating page hits into unique daily visits.
- The fingerprint **resets the next day** — no long-term tracking.
- The raw IP is **never stored in the fingerprint** — it cannot be reversed.

```php
// Count only unique visitors per day
$firewall->enableTracking(function (VisitInfo $visit) use ($pdo) {
    $exists = $pdo->prepare("SELECT 1 FROM visits WHERE fingerprint = ? AND DATE(visited_at) = CURDATE()")
                  ->execute([$visit->fingerprint]);
    if (!$exists->fetchColumn()) {
        // First visit of the day for this visitor
        $pdo->prepare("INSERT INTO visits ...")->execute($visit->toArray());
    }
});
```

### Manage tracking at runtime

```php
$firewall->disableTracking();
$firewall->isTrackingEnabled(); // bool
```

---

## Visit Filtering

Passing the firewall makes a request *legitimate* — it does not make it a *page view*. A missing font still reaches PHP (your rewrite rules send anything not on disk to `index.php`), a favicon probe is a sub-resource, and a form `POST` is not a new visit. Recorded as-is, all three inflate your statistics.

`$firewall->visits` decides what counts. **It never blocks anything** — it only guards the tracking callback, so a missing asset still gets a normal `404` instead of a `403`.

Enabled by default, filtering `GET` requests only and skipping known asset extensions and sub-resource paths.

```php
$firewall = XZeroProtect::init([
    'tracking' => [
        'filter'             => true,        // false = record everything, as before
        'when'               => 'immediate', // or 'shutdown' — see below
        'only_status'        => [200],       // 'shutdown' only; [] = any response
        'methods'            => ['GET'],     // [] accepts any method
        'use_sec_fetch_dest' => true,
        'track_dest'         => ['document'],
        'ignore_ajax'        => true,
        'ignore_prefetch'    => true,
        'ignore_extensions'  => [],          // added to the defaults
        'ignore_paths'       => [],          // added to the defaults
    ],
]);
```

### What gets filtered

| Signal | Effect |
|--------|--------|
| `Sec-Fetch-Dest` | The browser states what it wants the response for. `document` is a page; `font`, `image`, `style`, `script`, `empty`, `manifest`, … are not. Catches sub-resources served from clean routes, where there is no extension to match on. |
| `X-Requested-With` | jQuery-style XHR is not a page view. |
| `Sec-Purpose` / `Purpose` / `X-Moz` / `X-Purpose` | Prefetched and prerendered pages nobody has looked at yet. |
| HTTP method | Only `GET` counts by default; a form `POST` is not a new visit. |
| Path & extension | Fallback for clients that send no `Sec-Fetch-Dest`. |

`Sec-Fetch-Dest` can only **reject** a request, never wave one through. Typing `/robots.txt` in the address bar is a `document` navigation, but an explicit ignore rule still wins — the header removes false visits, it does not override your configuration.

```php
// Extend at runtime — every method is chainable
$firewall->visits->addIgnoredExtension('woff3');   // '.woff3' and 'woff3' both work
$firewall->visits->addIgnoredPath('/api/');        // matched as a path prefix
$firewall->visits->allowMethod('POST');
$firewall->visits->addTrackedDest('iframe');       // count embedded navigations too
$firewall->visits->ignoreAjax(false);
$firewall->visits->ignorePrefetch(false);
$firewall->visits->useSecFetchDest(false);

// Drop a default you want counted
$firewall->visits->removeIgnoredExtension('.svg');
$firewall->visits->removeIgnoredPath('/robots.txt');

// Your own logic — return false to discard the visit
$firewall->visits->addFilter('no-preview', fn($request) => !str_starts_with($request->path(), '/preview'));
$firewall->visits->removeFilter('no-preview');

// Inspect / debug
$firewall->visits->shouldTrack($request);  // bool
$firewall->visits->lastReason();           // 'extension:.woff2' | 'path:/favicon.ico' | 'method:POST' | null
```

A filter that throws is skipped rather than counted as a rejection, so a bug in your closure can never silently drop traffic from your statistics.

### Not counting 404s, redirects, and errors

The firewall runs before your router, so at that moment nobody knows whether the URL resolves. A visitor following a broken link to `/blog/hlelo-wrold` gets your 404 page — and, by default, a recorded visit.

Set `'when' => 'shutdown'` and the callback fires once the response is complete, when the status code is known:

```php
XZeroProtect::init([
    'tracking' => [
        'when'        => 'shutdown',
        'only_status' => [200],   // [] to record regardless of the response
    ],
]);
```

No change to your application code — the callback is simply invoked later, from a shutdown handler. The recorded `timestamp` is still the moment the visitor arrived, not the moment the response finished. Requests the filter already rejected are never deferred at all.

`only_status` applies to `shutdown` mode only; in `immediate` mode nothing has been routed yet, so there is no status to check.

<details>
<summary>View default tracking-ignore rules</summary>

| Category | Entries |
|----------|---------|
| Stylesheets & scripts | `.css` `.js` `.mjs` `.map` |
| Images | `.jpg` `.jpeg` `.png` `.gif` `.webp` `.avif` `.svg` `.ico` `.bmp` |
| Fonts | `.woff` `.woff2` `.ttf` `.otf` `.eot` |
| Media | `.mp3` `.m4a` `.wav` `.ogg` `.mp4` `.webm` |
| Paths | `/favicon.ico` `/apple-touch-icon` `/robots.txt` `/sitemap` `/ads.txt` `/browserconfig.xml` `/service-worker.js` `/sw.js` `/manifest.json` `/site.webmanifest` `/.well-known/` |

> **Note:** `.json`, `.html`, `.xml`, `.txt`, and `.pdf` are **not** in the extension list, because applications legitimately route them. The specific sub-resources among them are listed as paths instead. Edit these defaults in `rules/ignore_tracking.php`.

</details>

### Also handle it in your web server

The filter keeps bad data out of your statistics, but a missing asset still boots PHP. For Apache, answer it before PHP starts — the two work together, and the rewrite is the cheaper half:

```apache
RewriteCond %{REQUEST_FILENAME} !-f
RewriteCond %{REQUEST_FILENAME} !-d
RewriteRule \.(?:css|js|map|jpe?g|png|gif|webp|avif|svg|ico|woff2?|ttf|otf|eot|mp3|mp4|webm)$ - [NC,R=404,L]
```

Keep `.php`, `.env`, and `.asp` out of that list — those probes should reach the firewall so auto-ban can act on them.

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
│   ├── CrawlerVerifier.php   Trusted crawler detection with cached double-DNS
│   ├── Logger.php            Attack logging with rotation
│   ├── VisitInfo.php         Verified visit data object (tracking)
│   ├── VisitFilter.php       Decides which requests count as a page visit
│   └── DeviceInfo.php        Browser, OS, and device type parser
├── config/
│   └── config.php            Default configuration
├── rules/
│   ├── paths.php             Default blocked path patterns
│   ├── agents.php            Default blocked User-Agent signatures
│   ├── payloads.php          Default attack payload patterns (PCRE)
│   ├── crawlers.php          Trusted crawler definitions (UA + rDNS config)
│   └── ignore_tracking.php   Requests never counted as a page visit
└── tests/
    ├── XZeroProtectTest.php     PHPUnit test suite
    ├── VisitFilterTest.php      Visit-filtering test suite
    ├── CrawlerCacheTest.php     Crawler DNS-cache test suite
    └── DeferredTrackingTest.php Response-status tracking test suite
```

---

## Running Tests

```bash
composer install
composer test

# With detailed output
./vendor/bin/phpunit --testdox
```

---

## Requirements

- PHP **8.0** or higher
- Write permission on the storage directory

---

## License

Released under the [MIT License](LICENSE).  
Built by [Webrium](https://github.com/webrium).