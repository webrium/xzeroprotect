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

    private array   $config;
    private Storage $storage;
    private string  $mode;
    private array   $checks;
    private array   $autoBan;

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
            (int)  ($config['log']['keep_days']     ?? 30)
        );

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

        $request = new Request();

        // Always pass whitelisted IPs
        if ($this->ip->isWhitelisted($request->ip)) {
            return;
        }

        // Check for whitelisted paths
        foreach ($this->config['whitelist']['paths'] ?? [] as $allowedPath) {
            if (strpos($request->uri, $allowedPath) === 0) {
                return;
            }
        }

        // 1. Banned IP check (always runs regardless of mode)
        if ($this->ip->isBanned($request->ip)) {
            $this->block($request, 'banned_ip', 'IP is banned');
        }

        // 2. Rate limiting
        if ($this->checkEnabled('rate_limit')) {
            if ($this->rateLimit->isExceeded($request->ip)) {
                $this->handleViolation($request, 'rate_limit', 'Rate limit exceeded');
            }
        }

        // 3. Suspicious path
        if ($this->checkEnabled('blocked_path')) {
            if ($this->patterns->isSuspiciousPath($request->uri)) {
                $this->handleViolation($request, 'blocked_path', 'Suspicious URI: ' . $request->uri);
            }
        }

        // 4. User-Agent
        if ($this->checkEnabled('user_agent')) {
            if ($this->patterns->isSuspiciousAgent($request->userAgent)) {
                $this->handleViolation($request, 'user_agent', 'Suspicious UA: ' . substr($request->userAgent, 0, 100));
            }
        }

        // 5. Payload scanning
        if ($this->checkEnabled('payload')) {
            $label = $this->patterns->detectPayload($request->rawInput());
            if ($label !== null) {
                $this->handleViolation($request, 'payload', 'Payload match: ' . $label);
            }
        }

        // 6. Custom rules
        if ($this->checkEnabled('custom_rules')) {
            $result = $this->rules->evaluate($request);
            if ($result->isBlock()) {
                $this->handleViolation($request, 'custom_rule', $result->reason);
            } elseif ($result->isLog()) {
                $this->logger->log('custom_rule_log', $request, $result->reason);
            }
        }
    }

    // -------------------------------------------------------------------------
    // Manual controls
    // -------------------------------------------------------------------------

    /**
     * Enable or disable a specific check.
     * Keys: rate_limit | blocked_path | user_agent | payload | custom_rules
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
            $violations = $this->storage->incrementViolation($request->ip);
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

    private function defaultStoragePath(): string
    {
        return dirname(__DIR__) . '/storage';
    }

    private function defaultHtaccessPath(): string
    {
        return ($_SERVER['DOCUMENT_ROOT'] ?? getcwd()) . '/.htaccess';
    }

    private static function mergeConfig(array $defaults, array $overrides): array
    {
        foreach ($overrides as $key => $value) {
            if (is_array($value) && isset($defaults[$key]) && is_array($defaults[$key])) {
                $defaults[$key] = self::mergeConfig($defaults[$key], $value);
            } else {
                $defaults[$key] = $value;
            }
        }
        return $defaults;
    }
}