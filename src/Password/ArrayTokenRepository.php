<?php

declare(strict_types=1);

namespace Azera\Auth\Password;

use Azera\Security\Hasher;

/**
 * In-memory token repository for tests and short-lived processes.
 *
 * Tokens are stored hashed with SHA-256 alongside an expiry timestamp.
 * This implementation is not persistent across processes; for production
 * use {@see DbTokenRepository} or a cache-backed variant.
 */
class ArrayTokenRepository implements TokenRepositoryInterface
{
    /** @var array<string, array{user: mixed, hash: string, expires: int}> */
    private array $tokens = [];

    public function __construct(
        private Hasher $hasher = new Hasher(),
        private int $defaultExpires = 3600,
    ) {}

    public function create(mixed $user, int $expires): string
    {
        $this->deleteExpired();

        $plain = $this->hasher->token(32);
        $hash  = hash('sha256', $plain);
        $key   = $this->key($user);

        $this->tokens[$key . '|' . $hash] = [
            'user'    => $user,
            'hash'    => $hash,
            'expires' => time() + $expires,
        ];

        return $plain;
    }

    public function exists(mixed $user, string $token): bool
    {
        if ($token === '') {
            return false;
        }

        $hash = hash('sha256', $token);
        $key  = $this->key($user) . '|' . $hash;

        if (!isset($this->tokens[$key])) {
            return false;
        }

        return $this->tokens[$key]['expires'] > time();
    }

    public function delete(mixed $user, string $token): void
    {
        $hash = hash('sha256', $token);
        $key  = $this->key($user) . '|' . $hash;
        unset($this->tokens[$key]);
    }

    public function deleteExpired(): void
    {
        $now = time();
        foreach ($this->tokens as $key => $entry) {
            if ($entry['expires'] <= $now) {
                unset($this->tokens[$key]);
            }
        }
    }

    private function key(mixed $user): string
    {
        if (is_array($user)) {
            return 'user:' . (string) ($user['id'] ?? '');
        }

        if (is_object($user)) {
            foreach (['id', 'Id', 'ID'] as $prop) {
                if (isset($user->$prop)) {
                    return 'user:' . (string) $user->$prop;
                }
            }
            if (method_exists($user, 'getId')) {
                return 'user:' . (string) $user->getId();
            }
        }

        return 'user:';
    }
}