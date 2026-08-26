<?php

declare(strict_types=1);

namespace Azera\Auth\Provider;

/**
 * Loads users by credentials or identifier.
 *
 * Decouples guards from the storage layer. A guard authenticates a
 * credential bag; the provider knows how to find a user by email,
 * identifier, or a "remember me" token. This lets the same guards work
 * with the framework's Active Record {@see \Azera\Db\Model}, a custom
 * repository, or an external API.
 *
 * The shape of the returned user object is implementation-defined — it
 * may be a model instance, a plain array, or a DTO. Guards only require
 * that the provider return a consistent shape.
 */
interface UserProviderInterface
{
    /**
     * Find a user matching the given credentials.
     *
     * Typically the credential bag contains an identifier field
     * (e.g. `email`) and a `password`. The provider resolves the user
     * record by the identifier; password verification is the guard's
     * responsibility (so the guard can choose its hashing strategy).
     *
     * @param array<string, mixed> $credentials
     * @return mixed The user record, or null when not found.
     */
    public function findByCredentials(array $credentials): mixed;

    /**
     * Find a user by its identifier.
     *
     * @param mixed $identifier The user identifier (e.g. int id).
     * @return mixed The user record, or null when not found.
     */
    public function findById(mixed $identifier): mixed;

    /**
     * Find a user by a "remember me" token.
     *
     * @param string $identifier The identifier column value (e.g. email).
     * @param string $token       The plain-text token to match.
     * @return mixed The user record, or null when not found / token invalid.
     */
    public function findByRememberToken(string $identifier, string $token): mixed;

    /**
     * Update the "remember me" token for a user.
     *
     * @param mixed  $identifier The user identifier.
     * @param string $token      The new token (already hashed by the guard).
     */
    public function updateRememberToken(mixed $identifier, string $token): void;
}