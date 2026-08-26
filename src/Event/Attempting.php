<?php

declare(strict_types=1);

namespace Azera\Auth\Event;

/**
 * Fired before a guard attempts to authenticate credentials.
 *
 * The guard emits this event before looking up a user. Listeners can use
 * it to log attempts, throttle, or short-circuit (by throwing) — though
 * the standard throttle path is a separate {@see Lockout} event.
 */
final class Attempting extends AuthEvent
{
    /**
     * @param string               $guardName   Name of the guard attempting the login.
     * @param array<string, mixed> $credentials The credential bag (without the password when redacted).
     */
    public function __construct(
        public readonly string $guardName,
        public readonly array $credentials,
    ) {}
}