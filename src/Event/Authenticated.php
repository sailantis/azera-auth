<?php

declare(strict_types=1);

namespace Azera\Auth\Event;

/**
 * Fired after a guard successfully resolves a user (before persisting
 * the authenticated state). Use to react to a confirmed identity without
 * coupling to a specific guard.
 */
final class Authenticated extends AuthEvent
{
    /**
     * @param string $guardName Name of the guard that authenticated the user.
     * @param mixed  $user      The authenticated user record.
     */
    public function __construct(
        public readonly string $guardName,
        public readonly mixed $user,
    ) {}
}