<?php

declare(strict_types=1);

namespace Azera\Auth\Password;

/**
 * Storage for password-reset tokens.
 *
 * Tokens are stored hashed (never in the clear) with an expiry timestamp
 * and a single-use flag. The broker writes a token via {@see create()},
 * delivers the plain-text token out-of-band (via a PSR-14 event), and
 * consumes it via {@see exists()} + {@see delete()} after the password
 * is reset.
 */
interface TokenRepositoryInterface
{
    /**
     * Create and store a new reset token for the given user.
     *
     * Implementations MUST hash the token before storing it. The returned
     * value is the plain-text token (to be delivered to the user).
     *
     * @param mixed  $user     The user record (must expose an identifier).
     * @param int    $expires  Token lifetime in seconds.
     * @return string The plain-text token.
     */
    public function create(mixed $user, int $expires): string;

    /**
     * Whether a matching, unexpired, unused token exists for the user.
     *
     * Implementations MUST compare the hash of the supplied plain-text
     * token with {@see hash_equals}.
     *
     * @param mixed  $user     The user record.
     * @param string $token    The plain-text token supplied by the user.
     * @return bool
     */
    public function exists(mixed $user, string $token): bool;

    /**
     * Delete a token after it has been used (or expired).
     *
     * @param mixed  $user
     * @param string $token
     */
    public function delete(mixed $user, string $token): void;

    /**
     * Remove all expired tokens. Implementations should call this
     * periodically (e.g. on each {@see create()}).
     */
    public function deleteExpired(): void;
}