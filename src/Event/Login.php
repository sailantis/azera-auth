<?php

declare(strict_types=1);

namespace Azera\Auth\Event;

/**
 * Fired after a guard persists the authenticated state (e.g. after the
 * session id is set). Distinct from {@see Authenticated}, which fires
 * as soon as the user is resolved.
 */
final class Login extends AuthEvent
{
    /**
     * @param string $guardName Name of the guard that logged the user in.
     * @param mixed  $user      The authenticated user record.
     */
    public function __construct(
        public readonly string $guardName,
        public readonly mixed $user,
    ) {}
}