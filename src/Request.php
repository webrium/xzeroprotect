<?php

declare(strict_types=1);

namespace Webrium\XZeroProtect;

/**
 * Represents the current HTTP request.
 */
class Request
{
    public readonly string $ip;
    public readonly string $uri;
    public readonly string $method;
    public readonly string $userAgent;
    public readonly string $referer;
    public readonly array  $get;
    public readonly array  $post;
    public readonly array  $cookies;
    public readonly float  $time;

    public function __construct()
    {
        $this->ip        = $this->resolveIp();
        $this->uri       = $_SERVER['REQUEST_URI']       ?? '/';
        $this->method    = strtoupper($_SERVER['REQUEST_METHOD'] ?? 'GET');
        $this->userAgent = $_SERVER['HTTP_USER_AGENT']   ?? '';
        $this->referer   = $_SERVER['HTTP_REFERER']      ?? '';
        $this->get       = $_GET    ?? [];
        $this->post      = $_POST   ?? [];
        $this->cookies   = $_COOKIE ?? [];
        $this->time      = microtime(true);
    }

    private function resolveIp(): string
    {
        // Trust proxy headers only if explicitly configured — default to REMOTE_ADDR
        return $_SERVER['REMOTE_ADDR'] ?? '0.0.0.0';
    }

    /**
     * Returns all user-supplied input as a flat string for payload scanning.
     */
    public function rawInput(): string
    {
        $parts = [];

        foreach ([$this->get, $this->post, $this->cookies] as $bag) {
            foreach ($bag as $value) {
                $parts[] = is_array($value) ? implode(' ', $value) : (string) $value;
            }
        }

        // Also include raw POST body (for JSON APIs, etc.)
        $raw = file_get_contents('php://input');
        if ($raw !== false && $raw !== '') {
            $parts[] = $raw;
        }

        return implode(' ', $parts);
    }

    /**
     * Returns the path portion of the URI (without query string).
     */
    public function path(): string
    {
        return parse_url($this->uri, PHP_URL_PATH) ?? $this->uri;
    }
}
