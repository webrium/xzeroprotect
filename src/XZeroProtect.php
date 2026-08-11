<?php

declare(strict_types=1);

namespace Webrium\XZeroProtect;

/**
 * xZeroProtect — Lightweight file-based PHP Firewall
 *
 * @package webrium/xzeroprotect
 * @requires PHP 8.0+
 */
class XZeroProtect
{
    // Modes
    public const MODE_PRODUCTION = 'production';
    public const MODE_LEARNING   = 'learning';   // log only, never block
    public const MODE_OFF        = 'off';

    private static ?self $instance = null;

    // Public sub-components (accessible as $firewall->patterns, etc.)
    public PatternDetector $patterns;
    public IPManager       $ip;
    public RateLimiter     $rateLimit;
    public RuleEngine      $rules;
    public Logger          $logger;
    public ?ApacheBlocker  $apache = null;
    public CrawlerVerifier $crawlers;
    public VisitFilter     $visits;

    private array   $config;
    private Storage $storage;
    private string  $mode;
    private array   $checks;
    private array   $autoBan;

    // Visitor tracking
    public const TRACK_IMMEDIATE = 'immediate';
    public const TRACK_SHUTDOWN  = 'shutdown';

    private bool      $trackingEnabled  = false;
    private ?\Closure $visitorCallback  = null;
    private string    $trackingWhen     = self::TRACK_IMMEDIATE;
    private array     $trackedStatuses  = [];

    // -------------------------------------------------------------------------
    // Factory / constructor
    // -------------------------------------------------------------------------

    private function __construct(array $config)
    {
        $this->config = $config;
        $this->mode   = $config['mode'] ?? self::MODE_PRODUCTION;
        $this->checks = $config['checks'] ?? [];
        $this->autoBan = $config['auto_ban'] ?? [];

        // Storage
        $storagePath = $config['storage_path'] ?? $this->defaultStoragePath();
        $this->storage = new Storage($storagePath);

        // Sub-components
        $rulesDir          = $config['rules_path'] ?? dirname(__DIR__) . '/rules';
        $this->patterns    = new PatternDetector($rulesDir);
        $this->patterns->treatEmptyAgentAsSuspicious((bool) ($config['empty_user_agent_suspicious'] ?? false));
        $this->crawlers    = new CrawlerVerifier($rulesDir, $this->storage, $config['crawler_cache'] ?? []);
        $this->visits      = new VisitFilter($rulesDir, $config['tracking'] ?? []);
        $this->ip          = new IPManager($this->storage);
        $this->rateLimit   = new RateLimiter(
            $this->storage,
            (int) ($config['rate_limit']['max_requests'] ?? 60),
            (int) ($config['rate_limit']['per_seconds']  ?? 60)
        );
        $this->rules       = new RuleEngine();
        $this->logger      = new Logger(
            $this->storage,
            (bool) ($config['log']['enabled']       ?? true),
            (int)  ($config['log']['max_file_size'] ?? 10),
            (int)  ($config['log']['keep_days']     ?? 30),
            (bool) ($config['log']['auto_cleanup']  ?? true)
        );

        // Visitor tracking
        $this->setTrackingWhen((string) ($config['tracking']['when'] ?? self::TRACK_IMMEDIATE));
        $this->setTrackedStatuses((array) ($config['tracking']['only_status'] ?? [200]));

        // Whitelisted IPs
        foreach ($config['whitelist']['ips'] ?? [] as $cidr) {
            $this->ip->whitelist($cidr);
        }

        // Apache blocker
        if (!empty($config['apache_blocking'])) {
            $htPath       = $config['htaccess_path'] ?? $this->defaultHtaccessPath();
            $this->apache = new ApacheBlocker($htPath);
        }
    }

    /**
     * Create and return a new firewall instance.
     * The instance is also stored internally and retrievable via getInstance().
     *
     * @param array $config Override default config values
     */
    public static function init(array $config = []): static
    {
        $defaults = require dirname(__DIR__) . '/config/config.php';
        $merged   = self::mergeConfig($defaults, $config);
        self::$instance = new static($merged);
        return self::$instance;
    }

    /**
     * Retrieve the firewall instance created by init().
     * Use this to access logger, ip manager, etc. from anywhere in your app.
     *
     * @throws \RuntimeException if init() has not been called yet
     */
    public static function getInstance(): static
    {
        if (self::$instance === null) {
            throw new \RuntimeException(
                'xZeroProtect has not been initialized. Call XZeroProtect::init() first.'
            );
        }
        return self::$instance;
    }

    // -------------------------------------------------------------------------
    // Main entry point
    // -------------------------------------------------------------------------

    /**
     * Run all enabled firewall checks against the current request.
     * Call this at the very beginning of your bootstrap file.
     */
    public function run(): void
    {
        if ($this->mode === self::MODE_OFF) {
            return;
        }

        $request = new Request($this->config['trusted_proxies'] ?? []);

        // Always pass whitelisted IPs
        if ($this->ip->isWhitelisted($request->ip)) {
            return;
        }

        // Check for whitelisted paths. Matched on segment boundaries, so
        // whitelisting '/health' does not also exempt '/healthcheck-evil'.
        $path = $request->path();

        foreach ($this->config['whitelist']['paths'] ?? [] as $allowedPath) {
            $allowed = rtrim((string) $allowedPath, '/');

            if ($allowed !== '' && ($path === $allowed || str_starts_with($path, $allowed . '/'))) {
                return;
            }
        }

        // 1. Trusted crawler check — bypass all firewall checks
        if ($this->checkEnabled('crawler_check')) {
            if ($this->crawlers->isTrustedCrawler($request->ip, $request->userAgent)) {
                return; // verified legitimate crawler — let it through
            }
        }

        // 2. Banned IP check (always runs regardless of mode)
        if ($this->ip->isBanned($request->ip)) {
            $this->block($request, 'banned_ip', 'IP is banned');
        }

        // 3. Rate limiting
        if ($this->checkEnabled('rate_limit')) {
            if ($this->rateLimit->isExceeded($request->ip)) {
                $this->handleViolation($request, 'rate_limit', 'Rate limit exceeded');
            }
        }

        // 4. Suspicious path
        if ($this->checkEnabled('blocked_path')) {
            if ($this->patterns->isSuspiciousPath($request->uri)) {
                $this->handleViolation($request, 'blocked_path', 'Suspicious URI: ' . $request->uri);
            }
        }

        // 5. User-Agent
        if ($this->checkEnabled('user_agent')) {
            if ($this->patterns->isSuspiciousAgent($request->userAgent)) {
                $this->handleViolation($request, 'user_agent', 'Suspicious UA: ' . substr($request->userAgent, 0, 100));
            }
        }

        // 6. Payload scanning
        if ($this->checkEnabled('payload')) {
            $label = $this->patterns->detectPayload($request->rawInput());
            if ($label !== null) {
                $this->handleViolation($request, 'payload', 'Payload match: ' . $label);
            }
        }

        // 7. Custom rules
        if ($this->checkEnabled('custom_rules')) {
            $result = $this->rules->evaluate($request);
            if ($result->isBlock()) {
                $this->handleViolation($request, 'custom_rule', $result->reason);
            } elseif ($result->isLog()) {
                $this->logger->log('custom_rule_log', $request, $result->reason);
            }
        }

        // All checks passed — this is a real visit
        $this->recordVisit($request);
    }

    // -------------------------------------------------------------------------
    // Manual controls
    // -------------------------------------------------------------------------

    /**
     * Enable or disable a specific check.
     * Keys: crawler_check | rate_limit | blocked_path | user_agent | payload | custom_rules
     */
    public function enableCheck(string $check): void
    {
        $this->checks[$check] = true;
    }

    public function disableCheck(string $check): void
    {
        $this->checks[$check] = false;
    }

    public function setMode(string $mode): void
    {
        $this->mode = $mode;
    }

    public function getMode(): string
    {
        return $this->mode;
    }

    public function getStorage(): Storage
    {
        return $this->storage;
    }

    // -------------------------------------------------------------------------
    // Visitor tracking
    // -------------------------------------------------------------------------

    /**
     * Enable real-visitor tracking.
     *
     * The callback receives a VisitInfo object for every request that passes
     * all firewall checks. Use it to persist visits however you like.
     *
     * Example:
     *   $firewall->enableTracking(function(VisitInfo $visit) {
     *       DB::table('visits')->insert($visit->toArray());
     *   });
     *
     * @param \Closure(VisitInfo): void $callback
     */
    public function enableTracking(\Closure $callback): void
    {
        $this->trackingEnabled = true;
        $this->visitorCallback = $callback;
    }

    public function disableTracking(): void
    {
        $this->trackingEnabled = false;
    }

    public function isTrackingEnabled(): bool
    {
        return $this->trackingEnabled;
    }

    /**
     * When the tracking callback fires.
     *
     * 'immediate' — during run(), before the app has routed anything.
     * 'shutdown'  — once the response is complete, so the HTTP status is known
     *               and setTrackedStatuses() can drop 404s, redirects, and
     *               errors that would otherwise be counted as page visits.
     *
     * Any value other than 'shutdown' means immediate.
     */
    public function setTrackingWhen(string $when): void
    {
        $this->trackingWhen = strtolower(trim($when)) === self::TRACK_SHUTDOWN
            ? self::TRACK_SHUTDOWN
            : self::TRACK_IMMEDIATE;
    }

    public function getTrackingWhen(): string
    {
        return $this->trackingWhen;
    }

    /**
     * Response codes that count as a visit. Only consulted in 'shutdown' mode —
     * during run() nothing has been routed yet, so no status exists.
     *
     * An empty list records the visit whatever the response was.
     *
     * @param array<int,int> $codes
     */
    public function setTrackedStatuses(array $codes): void
    {
        $this->trackedStatuses = array_values(array_unique(array_map('intval', $codes)));
    }

    /** @return array<int,int> */
    public function getTrackedStatuses(): array
    {
        return $this->trackedStatuses;
    }

    // -------------------------------------------------------------------------
    // Private helpers
    // -------------------------------------------------------------------------

    private function checkEnabled(string $key): bool
    {
        return (bool) ($this->checks[$key] ?? true);
    }

    private function handleViolation(Request $request, string $type, string $reason): void
    {
        $this->logger->log($type, $request, $reason);

        if ($this->mode === self::MODE_LEARNING) {
            return; // log only — never block in learning mode
        }

        // Auto-ban logic
        if (!empty($this->autoBan['enabled'])) {
            $decayWindow = (int) ($this->autoBan['violation_window'] ?? 3600);

            // A single page load can fire far more requests than the rate
            // limit allows — a dashboard's async widgets, a flaky connection
            // retrying, a few browser tabs. Every one of those over-limit
            // requests is still blocked, but only the first per rate-limit
            // window is recorded as a violation, so one legitimate burst
            // cannot by itself accumulate an auto-ban. A scanner that keeps
            // exceeding the limit continuously still racks up one violation
            // every window, same as before.
            $cooldown = $type === 'rate_limit' ? $this->rateLimit->getWindow() : 0;

            $violations = $this->storage->incrementViolation($request->ip, $decayWindow, $cooldown);
            $threshold  = (int) ($this->autoBan['violations_threshold'] ?? 5);

            if ($violations >= $threshold) {
                $duration   = (int) ($this->autoBan['ban_duration'] ?? 86400);
                $permAfter  = (int) ($this->autoBan['permanent_after_bans'] ?? 3);
                $banCount   = $this->storage->getBanCount($request->ip);

                $finalDuration = ($banCount >= $permAfter - 1) ? 0 : $duration;

                $this->storage->ban($request->ip, $type . ': ' . $reason, $finalDuration);
                $this->storage->resetViolations($request->ip);

                // Sync to .htaccess if apache blocking is on and ban is permanent
                if ($this->apache !== null && $finalDuration === 0) {
                    $allBans = array_keys($this->ip->getAllBans());
                    $this->apache->sync($allBans);
                }

                $this->block($request, $type, 'Auto-banned after ' . $violations . ' violations');
            }
        }

        $this->block($request, $type, $reason);
    }

    /**
     * Terminate the request with the configured block response.
     */
    private function block(Request $request, string $type, string $reason): never
    {
        $code    = (int)    ($this->config['block_response']['code']    ?? 403);
        $message = (string) ($this->config['block_response']['message'] ?? 'Access Denied');

        http_response_code($code);
        header('Content-Type: text/plain; charset=UTF-8');
        echo $message;
        exit;
    }

    /**
     * Fire the visitor-tracking callback (if enabled) for a verified real visit.
     * Errors inside the callback are caught so they never break the main request.
     */
    private function recordVisit(Request $request): void
    {
        if (!$this->trackingEnabled || $this->visitorCallback === null) {
            return;
        }

        // Passing the firewall makes a request legitimate, not a page view.
        if (!$this->visits->shouldTrack($request)) {
            return;
        }

        // Built now, dispatched possibly later, so the recorded timestamp is
        // when the visitor arrived rather than when the response finished.
        $visit = new VisitInfo($request);

        if ($this->trackingWhen === self::TRACK_SHUTDOWN) {
            $this->deferToShutdown(function () use ($visit) {
                $this->dispatchVisit($visit);
            });

            return;
        }

        $this->dispatchVisit($visit);
    }

    /**
     * Hand the visit to the callback, unless the response turned out not to be
     * a page the visitor actually saw.
     */
    private function dispatchVisit(VisitInfo $visit): void
    {
        if ($this->trackingWhen === self::TRACK_SHUTDOWN
            && $this->trackedStatuses !== []
            && !in_array($this->responseStatus(), $this->trackedStatuses, true)
        ) {
            return;
        }

        try {
            ($this->visitorCallback)($visit);
        } catch (\Throwable) {
            // Tracking must never crash the application
        }
    }

    /**
     * Runs $callback after the response is complete. Overridable so the
     * deferred path can be tested without ending the process.
     */
    protected function deferToShutdown(\Closure $callback): void
    {
        register_shutdown_function($callback);
    }

    /**
     * Final HTTP status of the response. Overridable for the same reason;
     * falls back to 200 on SAPIs that do not track one.
     */
    protected function responseStatus(): int
    {
        $code = http_response_code();

        return is_int($code) ? $code : 200;
    }

    private function defaultStoragePath(): string
    {
        return dirname(__DIR__) . '/storage';
    }

    private function defaultHtaccessPath(): string
    {
        return ($_SERVER['DOCUMENT_ROOT'] ?? getcwd()) . '/.htaccess';
    }

    /**
     * Sections are merged key by key so overriding one check leaves the rest
     * alone. Value lists are replaced wholesale, because merging them by index
     * would leave the tail of the default behind — and would make it
     * impossible to clear a list, e.g. 'methods' => [] to accept any method.
     */
    private static function mergeConfig(array $defaults, array $overrides): array
    {
        foreach ($overrides as $key => $value) {
            if (is_array($value)
                && isset($defaults[$key])
                && is_array($defaults[$key])
                && !self::isList($value)
                && !self::isList($defaults[$key])
            ) {
                $defaults[$key] = self::mergeConfig($defaults[$key], $value);
            } else {
                $defaults[$key] = $value;
            }
        }
        return $defaults;
    }

    /**
     * array_is_list() equivalent; this package still supports PHP 8.0.
     */
    private static function isList(array $array): bool
    {
        return $array === [] || array_keys($array) === range(0, count($array) - 1);
    }
}