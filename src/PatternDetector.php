<?php

declare(strict_types=1);

namespace Webrium\XZeroProtect;

/**
 * Detects suspicious paths, user-agents, and payload patterns.
 */
class PatternDetector
{
    private array $paths    = [];
    private array $agents   = [];
    private array $payloads = [];  // [['label'=>string,'pattern'=>string]]

    public function __construct(string $rulesDir)
    {
        $this->paths    = require $rulesDir . '/paths.php';
        $this->agents   = require $rulesDir . '/agents.php';
        $this->payloads = require $rulesDir . '/payloads.php';
    }

    // -------------------------------------------------------------------------
    // Path detection
    // -------------------------------------------------------------------------

    public function isSuspiciousPath(string $uri): bool
    {
        $uri = urldecode(strtolower($uri));
        foreach ($this->paths as $pattern) {
            if (strpos($uri, strtolower($pattern)) !== false) {
                return true;
            }
        }
        return false;
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

    public function isSuspiciousAgent(string $userAgent): bool
    {
        if (trim($userAgent) === '') {
            return true; // empty UA is suspicious
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
        foreach ($this->payloads as $entry) {
            if (preg_match($entry['pattern'], $input)) {
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
}
