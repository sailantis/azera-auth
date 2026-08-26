<?php

declare(strict_types=1);

namespace Azera\Auth\Event;

/**
 * Fired when an authentication attempt fails — either because no user
 * matched the credentials or the password did not verify.
 */
final class Failed extends AuthEvent
{
    /**
     * @param string               $guardName   Name of the guard that rejected the attempt.
     * @param array<string, mixed> $credentials The credential bag (without the password when redacted).
     * @param mixed|null           $user        The user matched by identifier, if any, before password verification.
     */
    public function __construct(
        public readonly string $guardName,
        public readonly array $credentials,
        public readonly mixed $user = null,
    ) {}
}