<?php

declare(strict_types=1);

namespace Azera\Auth\Authorization;

/**
 * Default implementation of {@see Authorizable}.
 *
 * The trait expects the host class to supply:
 *  - `roles(): array<string>` returning the user's role identifiers, and
 *  - `permissions(): array<string>` returning the user's granted ability identifiers.
 *
 * Both may return an empty array; checks then simply fail. Applications
 * can override {@see can()} to delegate to a {@see Gate} for callback-
 * based abilities instead of the static permission list.
 *
 * Per the refactoring notes: trait properties are given defaults to
 * avoid "Typed property must not be accessed before initialization".
 */
trait AuthorizableTrait
{
    /** @return string[] */
    public function hasRole(string $role): bool
    {
        return in_array($role, $this->roles(), true);
    }

    public function hasAnyRole(string ...$roles): bool
    {
        if (empty($roles)) {
            return false;
        }
        foreach ($roles as $role) {
            if ($this->hasRole($role)) {
                return true;
            }
        }
        return false;
    }

    public function hasAllRoles(string ...$roles): bool
    {
        if (empty($roles)) {
            return true;
        }
        foreach ($roles as $role) {
            if (!$this->hasRole($role)) {
                return false;
            }
        }
        return true;
    }

    public function can(string $ability, mixed ...$args): bool
    {
        return in_array($ability, $this->permissions(), true);
    }

    public function cannot(string $ability, mixed ...$args): bool
    {
        return !$this->can($ability, ...$args);
    }

    /**
     * User's role identifiers. Override to return the actual list.
     *
     * @return string[]
     */
    abstract public function roles(): array;

    /**
     * User's granted ability identifiers. Override to return the actual list.
     *
     * @return string[]
     */
    abstract public function permissions(): array;
}