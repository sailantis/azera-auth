<?php

declare(strict_types=1);

namespace Azera\Auth\Password;

use Azera\Auth\Event\PasswordResetRequested;
use Azera\Security\Hasher;
use Closure;
use Psr\EventDispatcher\EventDispatcherInterface;

/**
 * Orchestrates the password-reset flow.
 *
 * Given a credential identifier (typically an email), the broker asks
 * a user-resolver to find the user, creates a reset token via a
 * {@see TokenRepositoryInterface}, and dispatches a
 * {@see PasswordResetRequested} event so a listener can deliver the
 * email/SMS containing the link. The actual reset is performed by
 * {@see reset()}, which verifies the token, applies the password update
 * callback, and deletes the (now single-use) token.
 */
class PasswordBroker
{
    public function __construct(
        private TokenRepositoryInterface $tokens,
        private Hasher $hasher = new Hasher(),
        private ?EventDispatcherInterface $dispatcher = null,
        private int $expires = 3600,
    ) {}

    /**
     * Generate a reset link for the user identified by $credentials.
     *
     * @param array<string, mixed> $credentials Identifier bag (e.g. `['email' => …]`).
     * @param Closure              $resolveUser fn(array $credentials): mixed  resolves the user, or null.
     * @return bool True when a token was created and the event dispatched.
     */
    public function sendResetLink(array $credentials, Closure $resolveUser): bool
    {
        $user = $resolveUser($credentials);

        if ($user === null) {
            return false;
        }

        $token = $this->tokens->create($user, $this->expires);

        $this->dispatcher?->dispatch(new PasswordResetRequested($user, $token));

        return true;
    }

    /**
     * Reset the password for $user using a previously issued token.
     *
     * @param mixed   $user        The user record.
     * @param string  $token       The plain-text reset token.
     * @param string  $newPassword The new plain-text password.
     * @param Closure $save        fn(mixed $user, string $hashedPassword): void  persists the new hash.
     * @return bool True on success, false when the token is invalid/expired.
     */
    public function reset(mixed $user, string $token, string $newPassword, Closure $save): bool
    {
        if (!$this->tokens->exists($user, $token)) {
            return false;
        }

        $save($user, $this->hasher->make($newPassword));

        $this->tokens->delete($user, $token);

        return true;
    }
}