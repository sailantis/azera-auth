<?php

declare(strict_types=1);

namespace Azera\Auth\Authorization;

use Closure;

/**
 * A registry of authorization callbacks (abilities) keyed by name.
 *
 * The gate evaluates an ability for a user by invoking the registered
 * callback with the user and any extra arguments. When the user itself
 * implements {@see Authorizable} and no callback is registered for the
 * ability, the gate falls back to the user's own {@see Authorizable::can()}
 * so models carrying a static permission list still work.
 *
 * Example:
 * ```php
 * $gate = new Gate();
 * $gate->define('billing.manage', fn($user) => $user->hasRole('admin'));
 * $gate->define('ticket.reply', fn($user, $ticket) => $ticket->assignee_id === $user->id);
 *
 * if (!$gate->allows('billing.manage', $user)) {
 *     throw new AuthorizationException();
 * }
 * ```
 */
class Gate
{
    /** @var array<string, Closure(mixed, mixed...): bool> */
    private array $abilities = [];

    /** @var Closure(mixed, string, mixed...): bool|null */
    private ?Closure $before = null;

    /**
     * Register an ability callback.
     *
     * @param string                                        $ability
     * @param Closure(mixed, mixed...): bool               $callback fn(mixed $user, mixed ...$args): bool
     */
    public function define(string $ability, Closure $callback): void
    {
        $this->abilities[$ability] = $callback;
    }

    /**
     * Register a global filter run before every ability check.
     *
     * Returning a non-null value short-circuits the check. Useful for
     * super-admin bypasses or deny-all overrides.
     *
     * @param Closure(mixed, string, mixed...): ?bool $callback
     */
    public function before(Closure $callback): void
    {
        $this->before = $callback;
    }

    /**
     * Whether the ability is granted to the user.
     *
     * @param string  $ability
     * @param mixed   $user  The authenticated user (or null for guest).
     * @param mixed   ...$args
     */
    public function allows(string $ability, mixed $user, mixed ...$args): bool
    {
        return $this->check($ability, $user, ...$args);
    }

    /**
     * Whether the ability is denied to the user.
     */
    public function denies(string $ability, mixed $user, mixed ...$args): bool
    {
        return !$this->check($ability, $user, ...$args);
    }

    /**
     * Evaluate an ability, throwing {@see AuthorizationException} when denied.
     */
    public function authorize(string $ability, mixed $user, mixed ...$args): void
    {
        if (!$this->check($ability, $user, ...$args)) {
            throw new AuthorizationException(sprintf('Ability "%s" denied.', $ability));
        }
    }

    /**
     * Whether a callback is registered for $ability.
     */
    public function has(string $ability): bool
    {
        return isset($this->abilities[$ability]);
    }

    private function check(string $ability, mixed $user, mixed ...$args): bool
    {
        if ($this->before !== null) {
            $result = ($this->before)($user, $ability, ...$args);
            if ($result !== null) {
                return $result;
            }
        }

        if (isset($this->abilities[$ability])) {
            return (bool) ($this->abilities[$ability])($user, ...$args);
        }

        if ($user instanceof Authorizable) {
            return $user->can($ability, ...$args);
        }

        return false;
    }
}