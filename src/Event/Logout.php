<?php

declare(strict_types=1);

namespace Azera\Auth\Event;

/**
 * Fired when a guard logs a user out (clears the persisted state).
 */
final class Logout extends AuthEvent
{
    /**
     * @param string $guardName Name of the guard that logged the user out.
     * @param mixed  $user      The user record, if it was still available at logout time.
     */
    public function __construct(
        public readonly string $guardName,
        public readonly mixed $user = null,
    ) {}
}