<?php

declare(strict_types=1);

namespace Azera\Auth\Guard;

use Azera\Http\Request;
use Azera\Security\GuardInterface;
use RuntimeException;

/**
 * Authenticates users via an OAuth2 authorization-code flow.
 *
 * The guard is intentionally split into two phases because OAuth2 is a
 * redirect-based flow, not a single-call credential check:
 *
 *  - {@see redirectToProvider()}: builds the authorization URL the user
 *    is redirected to (the "login" link).
 *  - {@see handleCallback()}: exchanges the `code` returned by the
 *    provider for an access token, then resolves the user via the
 *    provider's user endpoint.
 *
 * The underlying provider is any `League\OAuth2\Client\Provider\GenericProvider`
 * (or compatible). The package is a suggested dependency — the guard
 * throws on construction when it is absent.
 *
 * Resolved users are mapped to your application via a callable so this
 * guard does not assume a particular user model shape.
 */
class OAuth2Guard implements GuardInterface
{
    /**
     * @param object                   $provider        A League OAuth2 provider instance.
     * @param Request                  $request         The current HTTP request.
     * @param callable                 $mapUser         fn(object $resourceOwner): mixed  maps the provider's user to your user record.
     * @param callable                 $storeUser       fn(mixed $user): void  persists the authenticated state (e.g. set session id).
     * @param callable                 $loadUser        fn(): ?mixed  reads the persisted authenticated state.
     * @param callable                 $clearUser       fn(): void  clears the persisted state on logout.
     * @param string                   $name            Guard name.
     * @param string                   $stateKey        Session key holding the OAuth2 state for CSRF protection.
     * @param array<string, string>    $scopes          OAuth2 scopes to request.
     */
    public function __construct(
        private object $provider,
        private Request $request,
        private callable $mapUser,
        private callable $storeUser,
        private callable $loadUser,
        private callable $clearUser,
        private string $name = 'oauth2',
        private string $stateKey = '_oauth2_state',
        private array $scopes = ['email'],
    ) {
        if (!class_exists(\League\OAuth2\Client\Provider\GenericProvider::class)) {
            throw new RuntimeException(
                'OAuth2Guard requires league/oauth2-client. Install it with: composer require league/oauth2-client',
            );
        }
    }

    public function name(): string
    {
        return $this->name;
    }

    /**
     * Build the authorization URL the user is redirected to.
     *
     * The OAuth2 state is stored via the $storeState callable and must
     * be compared in {@see handleCallback()} to prevent CSRF.
     *
     * @param callable $storeState fn(string $state): void
     */
    public function redirectToProvider(callable $storeState): string
    {
        $url = $this->provider->getAuthorizationUrl(['scope' => $this->scopes]);
        $storeState($this->provider->getState());

        return $url;
    }

    /**
     * Handle the provider's redirect back to the application.
     *
     * Validates the state, exchanges the code for an access token,
     * fetches the resource owner, maps it to an application user, and
     * persists the authenticated state via the $storeUser callable.
     *
     * @param string|null $state   The state stored at redirect time.
     * @return mixed The resolved application user, or null on failure.
     */
    public function handleCallback(?string $state = null): mixed
    {
        $code          = (string) $this->request->query('code', '');
        $returnedState = (string) $this->request->query('state', '');

        if ($code === '' || $state === null || !hash_equals($state, $returnedState)) {
            return null;
        }

        try {
            $token         = $this->provider->getAccessToken('authorization_code', ['code' => $code]);
            $resourceOwner = $this->provider->getResourceOwner($token);
        } catch (\Throwable) {
            return null;
        }

        $user = ($this->mapUser)($resourceOwner);
        ($this->storeUser)($user);

        return $user;
    }

    public function attempt(array $credentials): bool
    {
        // OAuth2 is redirect-based; credential attempts are not applicable.
        return false;
    }

    public function check(): bool
    {
        return $this->user() !== null;
    }

    public function user(): mixed
    {
        return ($this->loadUser)();
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
        ($this->clearUser)();
    }
}