<?php

declare(strict_types=1);

namespace Azera\Auth\Provider;

use Closure;

/**
 * A user provider backed by callbacks.
 *
 * Useful for wiring an existing repository/API without implementing the
 * full {@see UserProviderInterface} by hand, and for tests where a fake
 * user store is quick to assemble.
 *
 * Each method delegates to the callback supplied in the constructor;
 * any callback left null returns the method's empty result.
 */
class CallbackUserProvider implements UserProviderInterface
{
    /**
     * @param Closure(array<string,mixed>): mixed        $findByCredentials
     * @param Closure(mixed): mixed                      $findById
     * @param Closure(string, string): mixed             $findByRememberToken
     * @param Closure(mixed, string): void|null          $updateRememberToken
     */
    public function __construct(
        private Closure $findByCredentials,
        private Closure $findById,
        private ?Closure $findByRememberToken = null,
        private ?Closure $updateRememberToken = null,
    ) {}

    public function findByCredentials(array $credentials): mixed
    {
        return ($this->findByCredentials)($credentials);
    }

    public function findById(mixed $identifier): mixed
    {
        return ($this->findById)($identifier);
    }

    public function findByRememberToken(string $identifier, string $token): mixed
    {
        if ($this->findByRememberToken === null) {
            return null;
        }

        return ($this->findByRememberToken)($identifier, $token);
    }

    public function updateRememberToken(mixed $identifier, string $token): void
    {
        if ($this->updateRememberToken !== null) {
            ($this->updateRememberToken)($identifier, $token);
        }
    }
}