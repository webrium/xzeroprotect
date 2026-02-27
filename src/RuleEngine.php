<?php

declare(strict_types=1);

namespace Webrium\XZeroProtect;

/**
 * Result returned by a custom rule callback.
 */
class RuleResult
{
    public const ACTION_PASS  = 'pass';
    public const ACTION_BLOCK = 'block';
    public const ACTION_LOG   = 'log';

    public string $action;
    public string $reason;

    private function __construct(string $action, string $reason = '')
    {
        $this->action = $action;
        $this->reason = $reason;
    }

    public static function pass(): self
    {
        return new self(self::ACTION_PASS);
    }

    public static function block(string $reason = 'custom rule'): self
    {
        return new self(self::ACTION_BLOCK, $reason);
    }

    public static function log(string $reason = 'custom rule'): self
    {
        return new self(self::ACTION_LOG, $reason);
    }

    public function isBlock(): bool { return $this->action === self::ACTION_BLOCK; }
    public function isLog(): bool   { return $this->action === self::ACTION_LOG; }
    public function isPass(): bool  { return $this->action === self::ACTION_PASS; }
}

/**
 * Manages and executes custom firewall rules.
 */
class RuleEngine
{
    /** @var array<string, array{callback: callable, priority: int, enabled: bool}> */
    private array $rules = [];

    /**
     * Register a custom rule.
     *
     * @param string   $name     Unique rule identifier
     * @param callable $callback function(Request): RuleResult
     * @param int      $priority Lower = runs first
     */
    public function add(string $name, callable $callback, int $priority = 50): void
    {
        $this->rules[$name] = [
            'callback' => $callback,
            'priority' => $priority,
            'enabled'  => true,
        ];
    }

    public function disable(string $name): void
    {
        if (isset($this->rules[$name])) {
            $this->rules[$name]['enabled'] = false;
        }
    }

    public function enable(string $name): void
    {
        if (isset($this->rules[$name])) {
            $this->rules[$name]['enabled'] = true;
        }
    }

    public function remove(string $name): void
    {
        unset($this->rules[$name]);
    }

    /**
     * Run all enabled rules against the request.
     * Returns the first non-pass result, or a pass result if all rules pass.
     */
    public function evaluate(Request $request): RuleResult
    {
        // Sort by priority
        $sorted = $this->rules;
        uasort($sorted, fn($a, $b) => $a['priority'] <=> $b['priority']);

        foreach ($sorted as $name => $rule) {
            if (!$rule['enabled']) {
                continue;
            }

            $result = ($rule['callback'])($request);

            if (!$result->isPass()) {
                return $result;
            }
        }

        return RuleResult::pass();
    }

    public function getRules(): array
    {
        return $this->rules;
    }
}
