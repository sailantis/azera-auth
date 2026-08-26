<?php

declare(strict_types=1);

namespace Azera\Auth\Guard;

use Azera\Auth\Event\Attempting;
use Azera\Auth\Event\Authenticated;
use Azera\Auth\Event\Failed;
use Azera\Auth\Event\Login;
use Azera\Auth\Event\Logout;
use Azera\Auth\Provider\TokenProviderInterface;
use Azera\Http\Request;
use Azera\Security\GuardInterface;

/**
 * Authenticates API requests by a bearer token or API key.
 *
 * The token is read, in priority order, from:
 *  1. the `Authorization: Bearer <token>` header,
 *  2. the `X-API-Key` header (or a configurable header name),
 *  3. the `_api_key` query parameter.
 *
 * The token is resolved to a user by a {@see TokenProviderInterface}.
 * Token comparison uses {@see hash_equals} when the provider returns a
 * stored hash, so timing attacks are mitigated.
 *
 * This guard is stateless: it does not persist anything in the session.
 * Each request re-resolves the user from the token. {@see logout()} is
 * a no-op by default; supply a token-revocation callback to invalidate.
 */
class TokenGuard implements GuardInterface
{
    private mixed $resolvedUser = null;

    private bool $resolved = false;

    /**
     * @param Request               $request  The current HTTP request.
     * @param TokenProviderInterface $provider Token → user resolver.
     * @param TokenGuardConfig|null $config   Optional tuning knobs; defaults to a fresh {@see TokenGuardConfig}.
     */
    public function __construct(
        private Request $request,
        private TokenProviderInterface $provider,
        private ?TokenGuardConfig $config = null,
    ) {
        $this->config ??= new TokenGuardConfig();
    }

    public function name(): string
    {
        return $this->config->name;
    }

    /**
     * Attempt is rarely used for token guards (the token comes from the
     * request, not a credential bag), but supported for parity with the
     * interface: the `token` credential is resolved to a user.
     *
     * @param array<string, mixed> $credentials Must contain a `token` key.
     */
    public function attempt(array $credentials): bool
    {
        $token = (string) ($credentials['token'] ?? '');
        if ($token === '') {
            return false;
        }

        $this->dispatch(new Attempting($this->config->name, ['token' => true]));

        $user = $this->provider->findByToken($token);
        if ($user === null) {
            $this->dispatch(new Failed($this->config->name, ['token' => true]));
            return false;
        }

        $this->dispatch(new Authenticated($this->config->name, $user));
        $this->resolvedUser = $user;
        $this->resolved     = true;
        $this->dispatch(new Login($this->config->name, $user));
        return true;
    }

    public function check(): bool
    {
        return $this->user() !== null;
    }

    public function user(): mixed
    {
        if ($this->resolved) {
            return $this->resolvedUser;
        }

        $token = $this->extractToken();
        if ($token === '') {
            return null;
        }

        $user = $this->provider->findByToken($token);
        $this->resolvedUser = $user;
        $this->resolved     = true;

        return $user;
    }

    public function id(): mixed
    {
        $user = $this->user();
        if ($user === null) {
            return null;
        }

        if (is_array($user)) {
            return $user['id'] ?? null;
        }

        if (is_object($user)) {
            foreach (['id', 'Id', 'ID'] as $prop) {
                if (isset($user->$prop)) {
                    return $user->$prop;
                }
            }
            foreach (['getId', 'id'] as $method) {
                if (method_exists($user, $method)) {
                    return $user->$method();
                }
            }
        }

        return null;
    }

    public function logout(): void
    {
        $user  = $this->resolvedUser;
        $token = $this->extractToken();

        if ($this->config->onLogout !== null && $token !== '') {
            ($this->config->onLogout)($token);
        }

        $this->resolvedUser = null;
        $this->resolved     = true;

        $this->dispatch(new Logout($this->config->name, $user));
    }

    /**
     * Extract the token from the request, in priority order.
     */
    private function extractToken(): string
    {
        $auth = $this->request->authorization();
        if (is_array($auth) && strtolower((string) $auth['scheme']) === 'bearer') {
            return trim((string) $auth['token']);
        }

        $header = $this->request->header($this->config->header);
        if (is_string($header) && $header !== '') {
            return trim($header);
        }

        $query = $this->request->query($this->config->queryParam);
        if (is_string($query) && $query !== '') {
            return trim($query);
        }

        return '';
    }

    private function dispatch(object $event): void
    {
        $this->config->dispatcher?->dispatch($event);
    }
}