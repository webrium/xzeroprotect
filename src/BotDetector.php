<?php

declare(strict_types=1);

namespace Webrium\XZeroProtect;

/**
 * Labels a User-Agent as a bot — or says nothing when it looks like a browser.
 *
 * This is for statistics, not security. It never blocks anything and it is not
 * asked about attackers: those are stopped by the firewall checks long before a
 * visit is recorded. What is left is the traffic that is harmless but is not a
 * person either — uptime monitors, HTTP clients, link-preview fetchers, search
 * and AI crawlers.
 *
 * It is deliberately cheap: a handful of substring searches and at most one
 * regex over a single header. No DNS, no disk, no state. Verified crawlers are
 * named by CrawlerVerifier instead, which already knows them.
 *
 * Lean towards "human": a person mislabelled as a bot disappears from the
 * numbers, a bot mislabelled as a person only nudges them.
 */
class BotDetector
{
    /** @var array<string,string> Lowercase needle => label */
    private array $agents = [];

    /** @var array<string,string> Regex => fallback label; group 1, when set, is the label */
    private array $patterns = [];

    private bool $nonBrowserIsBot = true;

    /**
     * @param array<int|string,string> $extraAgents Added to the defaults. A
     *        list entry ('mybot') is its own label; a map entry ('mybot' => 'My Bot')
     *        sets one.
     */
    public function __construct(string $rulesDir, array $extraAgents = [])
    {
        $rules = require $rulesDir . '/bots.php';

        foreach ($rules['agents'] ?? [] as $needle => $label) {
            $this->addAgent((string) $needle, (string) $label);
        }

        if (!empty($rules['pattern'])) {
            $this->addPattern((string) $rules['pattern'], 'bot');
        }

        foreach ($extraAgents as $needle => $label) {
            is_int($needle)
                ? $this->addAgent((string) $label)
                : $this->addAgent((string) $needle, (string) $label);
        }
    }

    // -------------------------------------------------------------------------
    // Detection
    // -------------------------------------------------------------------------

    /**
     * Returns a label for the bot ('Pulsetic', 'AhrefsBot', 'curl'), or null when
     * the User-Agent looks like a person's browser.
     */
    public function detect(string $userAgent): ?string
    {
        $userAgent = trim($userAgent);

        if ($userAgent === '') {
            return 'Empty User-Agent';
        }

        $lower = strtolower($userAgent);

        foreach ($this->agents as $needle => $label) {
            if (str_contains($lower, (string) $needle)) {
                return $label;
            }
        }

        foreach ($this->patterns as $regex => $fallback) {
            if (@preg_match((string) $regex, $userAgent, $m) === 1) {
                return isset($m[1]) && $m[1] !== '' ? $m[1] : $fallback;
            }
        }

        // Browsers never put a URL in their User-Agent; bots do it on purpose
        // so a site owner can find out who is calling ("+https://example.com/bot").
        if (str_contains($lower, 'http://') || str_contains($lower, 'https://')) {
            return 'Bot (URL in User-Agent)';
        }

        // Every mainstream browser has started its User-Agent with "Mozilla/"
        // since the 90s (Opera's old Presto engine used "Opera/"). Anything else
        // is a client library or an app, not someone reading a page.
        if ($this->nonBrowserIsBot
            && !str_starts_with($lower, 'mozilla/')
            && !str_starts_with($lower, 'opera/')
        ) {
            return 'Non-browser client';
        }

        return null;
    }

    public function isBot(string $userAgent): bool
    {
        return $this->detect($userAgent) !== null;
    }

    // -------------------------------------------------------------------------
    // Rules
    // -------------------------------------------------------------------------

    /**
     * Treat any User-Agent containing $needle as a bot. Case-insensitive.
     * Without a $label the needle itself is used.
     */
    public function addAgent(string $needle, ?string $label = null): self
    {
        $needle = strtolower(trim($needle));

        if ($needle !== '') {
            $this->agents[$needle] = $label !== null && $label !== '' ? $label : $needle;
        }

        return $this;
    }

    public function removeAgent(string $needle): self
    {
        unset($this->agents[strtolower(trim($needle))]);

        return $this;
    }

    /**
     * Add a regex. If it has a capture group, group 1 becomes the bot's label;
     * otherwise $label does.
     */
    public function addPattern(string $regex, string $label = 'bot'): self
    {
        if ($regex !== '') {
            $this->patterns[$regex] = $label;
        }

        return $this;
    }

    public function removePattern(string $regex): self
    {
        unset($this->patterns[$regex]);

        return $this;
    }

    /**
     * Whether a User-Agent that does not start with "Mozilla/" or "Opera/" counts
     * as a bot. On by default; turn it off if real visitors reach you through
     * an app that sends its own User-Agent.
     */
    public function treatNonBrowserAsBot(bool $enabled = true): self
    {
        $this->nonBrowserIsBot = $enabled;

        return $this;
    }

    /** @return array<string,string> */
    public function getAgents(): array
    {
        return $this->agents;
    }
}
