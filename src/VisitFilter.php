<?php

declare(strict_types=1);

namespace Webrium\XZeroProtect;

/**
 * Decides whether a request that passed every firewall check counts as a
 * real page visit.
 *
 * This component never blocks anything — it only guards the visitor-tracking
 * callback. A missing font, a favicon probe, or a form POST is a legitimate
 * request; it simply is not a page view.
 *
 * Checks run in this order, cheapest first:
 *   1. HTTP method   — exact match, empty list accepts any method
 *   2. prefetch      — speculative background load, nobody has seen it
 *   3. AJAX          — XHR, not a page
 *   4. Sec-Fetch-Dest— what the browser wants the response for
 *   5. ignored path  — case-insensitive prefix of the request path
 *   6. extension     — last path segment, case-insensitive
 *   7. custom filters— closures returning false discard the visit
 *
 * Sec-Fetch-Dest can only reject a request, never wave one through. A page
 * navigation to a path you deliberately ignored stays ignored — the header
 * removes false visits, it does not override your configuration.
 */
class VisitFilter
{
    private bool $enabled;

    private bool $useSecFetchDest;
    private bool $ignoreAjax;
    private bool $ignorePrefetch;

    /** @var array<int,string> Lowercase Sec-Fetch-Dest values that may count */
    private array $trackedDest = [];

    /** @var array<int,string> Lowercase, leading dot: '.woff2' */
    private array $extensions = [];

    /** @var array<int,string> Lowercase, leading slash: '/favicon.ico' */
    private array $paths = [];

    /** @var array<int,string> Uppercase methods; empty accepts any */
    private array $methods = [];

    /** @var array<string,\Closure> name => fn(Request): bool */
    private array $filters = [];

    private ?string $lastReason = null;

    public function __construct(string $rulesDir, array $config = [])
    {
        $defaults = $this->loadDefaults($rulesDir);

        $this->enabled         = (bool) ($config['filter']             ?? true);
        $this->useSecFetchDest = (bool) ($config['use_sec_fetch_dest'] ?? true);
        $this->ignoreAjax      = (bool) ($config['ignore_ajax']        ?? true);
        $this->ignorePrefetch  = (bool) ($config['ignore_prefetch']    ?? true);

        $this->setTrackedDest($config['track_dest'] ?? ['document']);

        // Config entries extend the defaults; use remove*() to drop a default.
        $this->addIgnoredExtensions(array_merge(
            $defaults['extensions']        ?? [],
            $config['ignore_extensions']   ?? []
        ));

        $this->addIgnoredPaths(array_merge(
            $defaults['paths']       ?? [],
            $config['ignore_paths']  ?? []
        ));

        $this->setMethods($config['methods'] ?? ['GET']);
    }

    // -------------------------------------------------------------------------
    // Decision
    // -------------------------------------------------------------------------

    /**
     * Returns true when the request should be handed to the tracking callback.
     * On false, lastReason() explains which check rejected it.
     */
    public function shouldTrack(Request $request): bool
    {
        $this->lastReason = null;

        if (!$this->enabled) {
            return true;
        }

        if ($this->methods !== [] && !in_array($request->method, $this->methods, true)) {
            return $this->reject('method:' . $request->method);
        }

        if ($this->ignorePrefetch && $request->isPrefetch()) {
            return $this->reject('prefetch');
        }

        if ($this->ignoreAjax && $request->isAjax()) {
            return $this->reject('ajax');
        }

        if ($this->useSecFetchDest) {
            $dest = $request->secFetchDest();

            // An absent header means an old or non-browser client; the path and
            // extension lists below stay the fallback for those.
            if ($dest !== '' && !in_array($dest, $this->trackedDest, true)) {
                return $this->reject('dest:' . $dest);
            }
        }

        $path = strtolower($request->path());

        foreach ($this->paths as $ignored) {
            if (str_starts_with($path, $ignored)) {
                return $this->reject('path:' . $ignored);
            }
        }

        $extension = $request->extension();
        if ($extension !== '' && in_array('.' . $extension, $this->extensions, true)) {
            return $this->reject('extension:.' . $extension);
        }

        foreach ($this->filters as $name => $filter) {
            // A broken custom filter must not lose the visit or break the app,
            // so a throwing filter is skipped rather than treated as a reject.
            try {
                $keep = $filter($request);
            } catch (\Throwable) {
                continue;
            }

            if ($keep === false) {
                return $this->reject('filter:' . $name);
            }
        }

        return true;
    }

    /**
     * Reason the last shouldTrack() call returned false, or null when it
     * returned true. Intended for debugging and tests.
     */
    public function lastReason(): ?string
    {
        return $this->lastReason;
    }

    // -------------------------------------------------------------------------
    // Extensions
    // -------------------------------------------------------------------------

    public function addIgnoredExtension(string $extension): self
    {
        $normalized = $this->normalizeExtension($extension);

        if ($normalized !== '' && !in_array($normalized, $this->extensions, true)) {
            $this->extensions[] = $normalized;
        }

        return $this;
    }

    /**
     * @param array<int,string> $extensions
     */
    public function addIgnoredExtensions(array $extensions): self
    {
        foreach ($extensions as $extension) {
            $this->addIgnoredExtension($extension);
        }

        return $this;
    }

    public function removeIgnoredExtension(string $extension): self
    {
        $normalized = $this->normalizeExtension($extension);

        $this->extensions = array_values(array_filter(
            $this->extensions,
            fn(string $known): bool => $known !== $normalized
        ));

        return $this;
    }

    /** @return array<int,string> */
    public function getIgnoredExtensions(): array
    {
        return $this->extensions;
    }

    // -------------------------------------------------------------------------
    // Paths
    // -------------------------------------------------------------------------

    public function addIgnoredPath(string $path): self
    {
        $normalized = $this->normalizePath($path);

        if ($normalized !== '' && !in_array($normalized, $this->paths, true)) {
            $this->paths[] = $normalized;
        }

        return $this;
    }

    /**
     * @param array<int,string> $paths
     */
    public function addIgnoredPaths(array $paths): self
    {
        foreach ($paths as $path) {
            $this->addIgnoredPath($path);
        }

        return $this;
    }

    public function removeIgnoredPath(string $path): self
    {
        $normalized = $this->normalizePath($path);

        $this->paths = array_values(array_filter(
            $this->paths,
            fn(string $known): bool => $known !== $normalized
        ));

        return $this;
    }

    /** @return array<int,string> */
    public function getIgnoredPaths(): array
    {
        return $this->paths;
    }

    // -------------------------------------------------------------------------
    // Methods
    // -------------------------------------------------------------------------

    /**
     * Replace the list of methods that may count as a visit.
     * An empty array accepts any method.
     *
     * @param array<int,string> $methods
     */
    public function setMethods(array $methods): self
    {
        $this->methods = [];

        foreach ($methods as $method) {
            $this->allowMethod($method);
        }

        return $this;
    }

    public function allowMethod(string $method): self
    {
        $normalized = strtoupper(trim($method));

        if ($normalized !== '' && !in_array($normalized, $this->methods, true)) {
            $this->methods[] = $normalized;
        }

        return $this;
    }

    /** @return array<int,string> */
    public function getMethods(): array
    {
        return $this->methods;
    }

    // -------------------------------------------------------------------------
    // Header signals
    // -------------------------------------------------------------------------

    /**
     * Replace the Sec-Fetch-Dest values that may count as a page visit.
     * Passing [] rejects every request that sends the header.
     *
     * @param array<int,string> $dest
     */
    public function setTrackedDest(array $dest): self
    {
        $this->trackedDest = [];

        foreach ($dest as $value) {
            $this->addTrackedDest($value);
        }

        return $this;
    }

    public function addTrackedDest(string $dest): self
    {
        $normalized = strtolower(trim($dest));

        if ($normalized !== '' && !in_array($normalized, $this->trackedDest, true)) {
            $this->trackedDest[] = $normalized;
        }

        return $this;
    }

    /** @return array<int,string> */
    public function getTrackedDest(): array
    {
        return $this->trackedDest;
    }

    public function useSecFetchDest(bool $use = true): self
    {
        $this->useSecFetchDest = $use;

        return $this;
    }

    public function ignoreAjax(bool $ignore = true): self
    {
        $this->ignoreAjax = $ignore;

        return $this;
    }

    public function ignorePrefetch(bool $ignore = true): self
    {
        $this->ignorePrefetch = $ignore;

        return $this;
    }

    // -------------------------------------------------------------------------
    // Custom filters
    // -------------------------------------------------------------------------

    /**
     * Register a custom decision. The closure receives the Request and returns
     * false to discard the visit; any other return value keeps it.
     *
     * @param \Closure(Request): bool $filter
     */
    public function addFilter(string $name, \Closure $filter): self
    {
        $this->filters[$name] = $filter;

        return $this;
    }

    public function removeFilter(string $name): self
    {
        unset($this->filters[$name]);

        return $this;
    }

    public function hasFilter(string $name): bool
    {
        return isset($this->filters[$name]);
    }

    // -------------------------------------------------------------------------
    // Enable / disable
    // -------------------------------------------------------------------------

    /**
     * When disabled, every request that reached tracking is recorded — the
     * behaviour of releases before this filter existed.
     */
    public function enable(): self
    {
        $this->enabled = true;

        return $this;
    }

    public function disable(): self
    {
        $this->enabled = false;

        return $this;
    }

    public function isEnabled(): bool
    {
        return $this->enabled;
    }

    // -------------------------------------------------------------------------
    // Private helpers
    // -------------------------------------------------------------------------

    /**
     * Loads the ignore lists, falling back to the packaged file when a custom
     * 'rules_path' was set before this rule set existed. Upgrading the package
     * must not fatal on a rules directory that predates it.
     */
    private function loadDefaults(string $rulesDir): array
    {
        $file = $rulesDir . '/ignore_tracking.php';

        if (!is_file($file)) {
            $file = dirname(__DIR__) . '/rules/ignore_tracking.php';
        }

        $defaults = require $file;

        return is_array($defaults) ? $defaults : [];
    }

    private function reject(string $reason): bool
    {
        $this->lastReason = $reason;

        return false;
    }

    /**
     * Accepts 'woff2', '.woff2', or '.WOFF2' and returns '.woff2'.
     */
    private function normalizeExtension(string $extension): string
    {
        $trimmed = strtolower(trim($extension));
        $trimmed = ltrim($trimmed, '.');

        return $trimmed === '' ? '' : '.' . $trimmed;
    }

    /**
     * Accepts 'api/', '/API/' and returns '/api/'.
     */
    private function normalizePath(string $path): string
    {
        $trimmed = strtolower(trim($path));

        if ($trimmed === '') {
            return '';
        }

        return str_starts_with($trimmed, '/') ? $trimmed : '/' . $trimmed;
    }
}
