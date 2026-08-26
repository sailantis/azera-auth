<?php

declare(strict_types=1);

namespace Azera\Auth\Event;

/**
 * Fired by the {@see \Azera\Auth\Verification\EmailVerification} flow
 * when a signed verification link is confirmed.
 */
final class Verified extends AuthEvent
{
    /**
     * @param mixed $user The user whose email is now verified.
     */
    public function __construct(
        public readonly mixed $user,
    ) {}
}