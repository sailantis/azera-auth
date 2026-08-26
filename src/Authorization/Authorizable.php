<?php

declare(strict_types=1);

namespace Azera\Auth\Authorization;

/**
 * Contract for users that can be checked against roles and abilities.
 *
 * Guards may return user records implementing this interface so the
 * {@see Gate} can authorize without coupling to a specific user model.
 * Applications can also implement it on their own model (or use the
 * {@see AuthorizableTrait}).
 */
interface Authorizable
{
    /**
     * Whether the user holds the given role.
     *
     * @param string $role Role identifier (e.g. 'admin').
     */
    public function hasRole(string $role): bool;

    /**
     * Whether the user holds any of the given roles.
     *
     * @param string ...$roles
     */
    public function hasAnyRole(string ...$roles): bool;

    /**
     * Whether the user holds all of the given roles.
     *
     * @param string ...$roles
     */
    public function hasAllRoles(string ...$roles): bool;

    /**
     * Whether the user is granted the given ability.
     *
     * @param string $ability  An ability identifier (e.g. 'billing.manage').
     * @param mixed  ...$args   Optional arguments forwarded to the callback.
     */
    public function can(string $ability, mixed ...$args): bool;

    /**
     * Whether the user is denied the given ability.
     */
    public function cannot(string $ability, mixed ...$args): bool;
}