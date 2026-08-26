<?php

declare(strict_types=1);

namespace Azera\Auth\Guard;

use Azera\Auth\Event\Attempting;
use Azera\Auth\Event\Authenticated;
use Azera\Auth\Event\Failed;
use Azera\Auth\Event\Lockout;
use Azera\Auth\Event\Login;
use Azera\Auth\Event\Logout;
use Azera\Auth\Provider\UserProviderInterface;
use Azera\Http\Session;
use Azera\Security\GuardInterface;
use Azera\Security\Hasher;
use RuntimeException;

/**
 * Session-based authentication guard.
 *
 * Authenticates a credential bag against a {@see UserProviderInterface},
 * verifying the `password` field with a {@see Hasher}. On success the
 * user identifier is persisted in the session and a {@see Login} event is
 * dispatched. Optional "remember me" support issues a long-lived cookie
 * backed by a provider-stored token, so the session can be restored
 * across browser restarts.
 *
 * Login throttling is delegated to {@see RateLimiter} when one is
 * supplied — exceeding the limit emits a {@see Lockout} event and the
 * attempt short-circuits.
 *
 * Events are dispatched through the optional PSR-14 dispatcher; when no
 * dispatcher is supplied, the guard works without emitting events (the
 * auth flow itself does not depend on listeners).
 */
class SessionGuard implements GuardInterface
{
    /** Key in the session that holds the authenticated user id. */
    public const SESSION_KEY = '_auth_user_id';

    /** Name of the "remember me" cookie. */
    public const REMEMBER_COOKIE = 'remember_web';

    /**
     * @param UserProviderInterface $provider User loader (required).
     * @param Session               $session  Session store (required).
     * @param Hasher                $hasher   Password verifier (required).
     * @param SessionGuardConfig|null $config Optional tuning knobs; defaults to a fresh {@see SessionGuardConfig}.
     */
    public function __construct(
        private UserProviderInterface $provider,
        private Session $session,
        private Hasher $hasher,
        private ?SessionGuardConfig $config = null,
    ) {
        $this->config ??= new SessionGuardConfig();
    }

    public function name(): string
    {
        return $this->config->name;
    }

    public function attempt(array $credentials): bool
    {
        $identifier = $this->identifier($credentials);

        if ($this->isThrottled($identifier)) {
            return false;
        }

        $this->dispatch(new Attempting($this->config->name, $this->redactCredentials($credentials)));

        $user = $this->provider->findByCredentials($credentials);

        $password = (string) ($credentials[$this->config->passwordField] ?? '');

        if ($user === null || $password === '' || !$this->hasher->verify($password, $this->passwordHash($user))) {
            $this->dispatch(new Failed($this->config->name, $this->redactCredentials($credentials), $user));
            return false;
        }

        $this->dispatch(new Authenticated($this->config->name, $user));

        $this->login($user, $this->wantsRememberMe($credentials));

        return true;
    }

    /**
     * Persist the authenticated state for a user, bypassing credential
     * verification. Useful after an OAuth callback or a "remember me"
     * cookie restoration.
     *
     * @param mixed $user     The user record to log in.
     * @param bool  $remember Whether to issue a "remember me" cookie.
     */
    public function login(mixed $user, bool $remember = false): void
    {
        $this->session->set(self::SESSION_KEY, $this->userId($user));

        if ($remember && $this->config->cookies !== null) {
            $this->issueRememberCookie($user);
        }

        $this->dispatch(new Login($this->config->name, $user));
    }

    public function check(): bool
    {
        return $this->id() !== null;
    }

    public function user(): mixed
    {
        $id = $this->id();

        if ($id === null) {
            $user = $this->userFromRememberCookie();
            if ($user !== null) {
                $this->login($user, false);
                return $user;
            }
            return null;
        }

        return $this->provider->findById($id);
    }

    public function id(): mixed
    {
        return $this->session->get(self::SESSION_KEY);
    }

    public function logout(): void
    {
        $user = $this->user();

        $this->session->remove(self::SESSION_KEY);

        if ($this->config->cookies !== null) {
            $this->config->cookies->delete(self::REMEMBER_COOKIE);
            $this->forgetRememberToken($user);
        }

        $this->dispatch(new Logout($this->config->name, $user));
    }

    // --- helpers -------------------------------------------------------------

    /**
     * Extract the identifier (e.g. email) from the credential bag.
     */
    private function identifier(array $credentials): string
    {
        if ($this->config->identifier !== null) {
            return (string) ($this->config->identifier)($credentials);
        }

        return (string) ($credentials['email'] ?? '');
    }

    /**
     * Apply the rate limiter, emitting a {@see Lockout} when exceeded.
     */
    private function isThrottled(string $identifier): bool
    {
        if ($this->config->rateLimiter === null || $identifier === '') {
            return false;
        }

        $key = $this->config->rateLimitKey . $identifier;

        if ($this->config->rateLimiter->isLimited($key, $this->config->maxAttempts)) {
            $this->dispatch(new Lockout($this->config->name, $key));
            return true;
        }

        $this->config->rateLimiter->limit($key, $this->config->maxAttempts, $this->config->decaySeconds);

        return false;
    }

    /**
     * Whether the credential bag requested "remember me".
     */
    private function wantsRememberMe(array $credentials): bool
    {
        return (bool) ($credentials['remember'] ?? false);
    }

    /**
     * Issue a "remember me" cookie backed by a provider-stored token.
     */
    private function issueRememberCookie(mixed $user): void
    {
        $identifier = $this->userIdentifierForToken($user);
        $plain      = $this->hasher->token(32);
        $this->provider->updateRememberToken($this->userId($user), hash('sha256', $plain));

        $this->config->cookies->set(
            self::REMEMBER_COOKIE,
            $identifier . '|' . $plain,
            time() + ($this->config->rememberMinutes * 60),
        );
    }

    /**
     * Resolve a user from a valid "remember me" cookie, if present.
     */
    private function userFromRememberCookie(): mixed
    {
        if ($this->config->cookies === null) {
            return null;
        }

        $value = $this->config->cookies->get(self::REMEMBER_COOKIE);
        if (!is_string($value) || !str_contains($value, '|')) {
            return null;
        }

        [$identifier, $plain] = explode('|', $value, 2);
        if ($identifier === '' || $plain === '') {
            return null;
        }

        $user = $this->provider->findByRememberToken($identifier, hash('sha256', $plain));

        return $user;
    }

    /**
     * Clear the provider's "remember me" token on logout.
     */
    private function forgetRememberToken(mixed $user): void
    {
        if ($user === null) {
            return;
        }

        $this->provider->updateRememberToken($this->userId($user), '');
    }

    /**
     * Read the password hash from a user record.
     *
     * Supports arrays, objects with public properties, and objects
     * exposing a `passwordHash()`/`getPasswordHash()` accessor.
     */
    private function passwordHash(mixed $user): string
    {
        if (is_array($user)) {
            return (string) ($user['password_hash'] ?? $user['password'] ?? '');
        }

        if (is_object($user)) {
            foreach (['password_hash', 'passwordHash', 'password'] as $prop) {
                if (isset($user->$prop)) {
                    return (string) $user->$prop;
                }
            }
            foreach (['passwordHash', 'getPasswordHash'] as $method) {
                if (method_exists($user, $method)) {
                    return (string) $user->$method();
                }
            }
        }

        return '';
    }

    /**
     * Read the user identifier from a user record.
     */
    private function userId(mixed $user): mixed
    {
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

    /**
     * Read the identifier used as the "remember me" token column.
     */
    private function userIdentifierForToken(mixed $user): string
    {
        if (is_array($user)) {
            return (string) ($user['email'] ?? $user['id'] ?? '');
        }

        if (is_object($user)) {
            foreach (['email', 'Email'] as $prop) {
                if (isset($user->$prop)) {
                    return (string) $user->$prop;
                }
            }
            foreach (['getEmail', 'email'] as $method) {
                if (method_exists($user, $method)) {
                    return (string) $user->$method();
                }
            }
        }

        return (string) $this->userId($user);
    }

    /**
     * Strip the password from the credential bag for event payloads.
     *
     * @return array<string, mixed>
     */
    private function redactCredentials(array $credentials): array
    {
        $redacted = $credentials;
        unset($redacted[$this->config->passwordField]);
        return $redacted;
    }

    /**
     * Dispatch an event when a dispatcher is available.
     */
    private function dispatch(object $event): void
    {
        $this->config->dispatcher?->dispatch($event);
    }
}