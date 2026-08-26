<?php

declare(strict_types=1);

namespace Azera\Auth\Event;

/**
 * Fired when the rate limiter denies a login attempt because the
 * configured threshold was reached. The standard guard path emits this
 * before performing the lookup so no further work is done while the
 * account/IP is throttled.
 */
final class Lockout extends AuthEvent
{
    /**
     * @param string $guardName Name of the guard that hit the limit.
     * @param string $key       The rate-limit key (e.g. `login:user@example.com`).
     */
    public function __construct(
        public readonly string $guardName,
        public readonly string $key,
    ) {}
}