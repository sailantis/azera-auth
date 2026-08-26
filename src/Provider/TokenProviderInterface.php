<?php

declare(strict_types=1);

namespace Azera\Auth\Provider;

/**
 * Loads a user by an authentication token.
 *
 * Used by the {@see \Azera\Auth\Guard\TokenGuard}. Distinct from
 * {@see UserProviderInterface} because token resolution often has
 * different storage (a `api_tokens` table vs the `users` table) and
 * timing-safe comparison requirements.
 */
interface TokenProviderInterface
{
    /**
     * Resolve a user from a plain-text or hashed token.
     *
     * Implementations MUST use {@see hash_equals} when comparing against
     * a stored hash to mitigate timing attacks.
     *
     * @param string $token The token as received from the request.
     * @return mixed The user record, or null when the token is invalid/revoked.
     */
    public function findByToken(string $token): mixed;
}