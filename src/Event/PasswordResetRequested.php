<?php

declare(strict_types=1);

namespace Azera\Auth\Event;

/**
 * Fired by the {@see \Azera\Auth\Password\PasswordBroker} when a reset
 * link is generated and (typically) about to be delivered. Listeners
 * send the actual email/notifications.
 */
final class PasswordResetRequested extends AuthEvent
{
    /**
     * @param mixed  $user  The user the reset was requested for.
     * @param string $token The plain-text reset token (only sent to the listener, never persisted in the clear).
     */
    public function __construct(
        public readonly mixed $user,
        public readonly string $token,
    ) {}
}