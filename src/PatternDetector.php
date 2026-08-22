<?php

declare(strict_types=1);

namespace Webrium\XZeroProtect;

/**
 * Detects suspicious paths, user-agents, and payload patterns.
 */
class PatternDetector
{
    private array $paths        = [];
    private array $agents       = [];
    private array $payloads     = [];  // [['label'=>string,'pattern'=>string]]
    private array $exemptFields = [];

    private bool $emptyAgentIsSuspicious = false;

    public function __construct(string $rulesDir)
    {
        $this->paths    = require $rulesDir . '/paths.php';
        $this->agents   = require $rulesDir . '/agents.php';
        $this->payloads = require $rulesDir . '/payloads.php';
    }

    // -------------------------------------------------------------------------
    // Path detection
    // -------------------------------------------------------------------------

    /**
     * Matches the request path against the blocked-path list.
     *
     * Patterns are matched per path segment, never as a loose substring of the
     * whole URI. '/wp-admin/setup-config.php' is a probe; an article at
     * '/posts/wordpress-security-vulnerabilities-2026' is not, and a firewall
     * that cannot tell them apart 403s paying visitors and — through auto-ban —
     * locks them out for a day.
     *
     * The query string is deliberately excluded. Attacks carried in query
     * values are the payload scanner's job; matching path names against them
     * turns an ordinary site search into a ban.
     *
     * Three kinds of pattern:
     *   '../', '%2e%2e'  raw signature, matched anywhere — always hostile
     *   '.env', '.sql'   extension, matched against the end of a segment
     *   'wp-admin'       name, matched against a whole segment, with or
     *                    without a file extension
     */
    public function isSuspiciousPath(string $uri): bool
    {
        $rawPath  = strtolower($this->stripQuery($uri));
        $path     = self::normalize($rawPath);
        $segments = $this->segments($path);

        foreach ($this->paths as $pattern) {
            $pattern = strtolower(trim($pattern));

            if ($pattern === '') {
                continue;
            }

            if ($this->isRawSignature($pattern)) {
                if (strpos($path, $pattern) !== false || strpos($rawPath, $pattern) !== false) {
                    return true;
                }
                continue;
            }

            if ($pattern[0] === '.') {
                foreach ($segments as $segment) {
                    // '.env' matches '.env', 'backup.env', and '.env.bak'
                    if ($segment === $pattern
                        || str_ends_with($segment, $pattern)
                        || str_starts_with($segment, $pattern . '.')
                    ) {
                        return true;
                    }
                }
                continue;
            }

            foreach ($segments as $segment) {
                // 'wp-login' matches 'wp-login' and 'wp-login.php'
                if ($segment === $pattern || $this->withoutExtension($segment) === $pattern) {
                    return true;
                }
            }
        }

        return false;
    }

    /**
     * Repeatedly percent-decodes until the value stops changing, so a
     * double-encoded '..%252f' is seen for what it is. Bounded to keep a
     * crafted input from looping.
     */
    public static function normalize(string $value): string
    {
        for ($pass = 0; $pass < 3; $pass++) {
            $decoded = urldecode($value);

            if ($decoded === $value) {
                break;
            }

            $value = $decoded;
        }

        return str_replace("\0", '', $value);
    }

    private function stripQuery(string $uri): string
    {
        $mark = strpos($uri, '?');

        return $mark === false ? $uri : substr($uri, 0, $mark);
    }

    /**
     * @return array<int,string>
     */
    private function segments(string $path): array
    {
        return array_values(array_filter(
            explode('/', str_replace('\\', '/', $path)),
            fn(string $segment): bool => $segment !== ''
        ));
    }

    /**
     * Traversal signatures contain a separator or an escape, so they can never
     * be a legitimate segment name and are matched raw.
     */
    private function isRawSignature(string $pattern): bool
    {
        return str_contains($pattern, '/')
            || str_contains($pattern, '\\')
            || str_contains($pattern, '%');
    }

    private function withoutExtension(string $segment): string
    {
        $dot = strrpos($segment, '.');

        if ($dot === false || $dot === 0) {
            return $segment;
        }

        $extension = substr($segment, $dot + 1);

        return preg_match('/^[a-z0-9]{1,6}$/', $extension) === 1
            ? substr($segment, 0, $dot)
            : $segment;
    }

    public function addPath(string $pattern): void
    {
        $this->paths[] = $pattern;
    }

    public function addPaths(array $patterns): void
    {
        foreach ($patterns as $p) {
            $this->addPath($p);
        }
    }

    public function removePath(string $pattern): void
    {
        $this->paths = array_values(array_filter(
            $this->paths,
            fn($p) => strtolower($p) !== strtolower($pattern)
        ));
    }

    public function getPaths(): array
    {
        return $this->paths;
    }

    // -------------------------------------------------------------------------
    // User-Agent detection
    // -------------------------------------------------------------------------

    /**
     * An absent User-Agent is unusual, not hostile: feed readers, uptime
     * probes, and some proxies send none. Treating it as an attack feeds
     * auto_ban and locks those clients out, so it is off by default.
     */
    public function treatEmptyAgentAsSuspicious(bool $suspicious = true): void
    {
        $this->emptyAgentIsSuspicious = $suspicious;
    }

    public function isSuspiciousAgent(string $userAgent): bool
    {
        if (trim($userAgent) === '') {
            return $this->emptyAgentIsSuspicious;
        }

        $ua = strtolower($userAgent);
        foreach ($this->agents as $keyword) {
            if (strpos($ua, strtolower($keyword)) !== false) {
                return true;
            }
        }
        return false;
    }

    public function addAgent(string $keyword): void
    {
        $this->agents[] = $keyword;
    }

    public function removeAgent(string $keyword): void
    {
        $this->agents = array_values(array_filter(
            $this->agents,
            fn($a) => strtolower($a) !== strtolower($keyword)
        ));
    }

    public function getAgents(): array
    {
        return $this->agents;
    }

    // -------------------------------------------------------------------------
    // Payload detection
    // -------------------------------------------------------------------------

    /**
     * Returns the label of the first matching payload pattern, or null if clean.
     */
    public function detectPayload(string $input): ?string
    {
        // Match the decoded form as well as what arrived, so a double-encoded
        // payload cannot hide behind one round of percent-escaping.
        $decoded = self::normalize($input);

        foreach ($this->payloads as $entry) {
            if (preg_match($entry['pattern'], $input) || preg_match($entry['pattern'], $decoded)) {
                return $entry['label'];
            }
        }

        return null;
    }

    public function addPayload(string $pattern, string $label = 'custom'): void
    {
        $this->payloads[] = ['label' => $label, 'pattern' => $pattern];
    }

    public function removePayload(string $label): void
    {
        $this->payloads = array_values(array_filter(
            $this->payloads,
            fn($p) => $p['label'] !== $label
        ));
    }

    public function getPayloads(): array
    {
        return $this->payloads;
    }

    public function exemptField(string $fieldName): void
    {
        $this->exemptFields[strtolower(trim($fieldName))] = true;
    }

    public function exemptFields(array $fieldNames): void
    {
        foreach ($fieldNames as $name) {
            $this->exemptField((string) $name);
        }
    }

    public function getExemptFields(): array
    {
        return array_keys($this->exemptFields);
    }

    public function clearExemptFields(): void
    {
        $this->exemptFields = [];
    }
}
