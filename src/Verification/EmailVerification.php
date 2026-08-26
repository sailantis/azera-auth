<?php

declare(strict_types=1);

namespace Azera\Auth\Verification;

use Azera\Auth\Event\Verified;
use Azera\Security\Hasher;
use Closure;
use Psr\EventDispatcher\EventDispatcherInterface;

/**
 * Signed-link email verification flow.
 *
 * Issues a signed verification link for a user, verifies the link's
 * signature and expiry, and marks the user as verified via a callback.
 * Tokens are generated with {@see Hasher::token()} and signed with a
 * server-side secret so the link is self-contained (no storage needed
 * for verification — the signature encodes the user id + expiry).
 */
class EmailVerification
{
    public function __construct(
        private string $secret,
        private Hasher $hasher = new Hasher(),
        private ?EventDispatcherInterface $dispatcher = null,
        private int $expires = 86400,
    ) {}

    /**
     * Generate a signed verification token for the given user.
     *
     * @param mixed $user The user record (must expose an identifier).
     * @return string A token to embed in the verification link (e.g. `?token=…`).
     */
    public function createToken(mixed $user): string
    {
        $id      = $this->userId($user);
        $expires = time() + $this->expires;

        $signature = $this->signature($id, $expires);
        $payload   = base64_encode(json_encode(['id' => $id, 'exp' => $expires], JSON_THROW_ON_ERROR));

        return $payload . '.' . $signature;
    }

    /**
     * Verify a signed token and mark the user as verified.
     *
     * @param string  $token   The token from the verification link.
     * @param Closure $resolve fn(string $userId): mixed  resolves the user from the id.
     * @param Closure $mark    fn(mixed $user): void  persists the verified state.
     * @return bool True on success, false when the token is invalid/expired.
     */
    public function verify(string $token, Closure $resolve, Closure $mark): bool
    {
        $payload = $this->parse($token);

        if ($payload === null) {
            return false;
        }

        if ($payload['exp'] <= time()) {
            return false;
        }

        $user = $resolve((string) $payload['id']);
        if ($user === null) {
            return false;
        }

        $mark($user);

        $this->dispatcher?->dispatch(new Verified($user));

        return true;
    }

    /**
     * Build the HMAC signature for an id + expiry pair.
     */
    private function signature(string $id, int $expires): string
    {
        return hash_hmac('sha256', $id . '|' . $expires, $this->secret);
    }

    /**
     * Decode and validate a token's signature.
     *
     * @return array{id: string, exp: int}|null
     */
    private function parse(string $token): ?array
    {
        $parts = explode('.', $token, 2);
        if (count($parts) !== 2) {
            return null;
        }

        [$payload, $signature] = $parts;
        $decoded = json_decode((string) base64_decode($payload, true), true);
        if (!is_array($decoded) || !isset($decoded['id'], $decoded['exp'])) {
            return null;
        }

        $expected = $this->signature((string) $decoded['id'], (int) $decoded['exp']);
        if (!hash_equals($expected, $signature)) {
            return null;
        }

        return ['id' => (string) $decoded['id'], 'exp' => (int) $decoded['exp']];
    }

    private function userId(mixed $user): string
    {
        if (is_array($user)) {
            return (string) ($user['id'] ?? '');
        }

        if (is_object($user)) {
            foreach (['id', 'Id', 'ID'] as $prop) {
                if (isset($user->$prop)) {
                    return (string) $user->$prop;
                }
            }
            foreach (['getId', 'id'] as $method) {
                if (method_exists($user, $method)) {
                    return (string) $user->$method();
                }
            }
        }

        return '';
    }
}