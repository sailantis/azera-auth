<?php

declare(strict_types=1);

namespace Azera\Auth\Guard;

use Azera\Auth\Event\Attempting;
use Azera\Auth\Event\Authenticated;
use Azera\Auth\Event\Failed;
use Azera\Auth\Event\Login;
use Azera\Auth\Event\Logout;
use Azera\Auth\Provider\UserProviderInterface;
use Azera\Http\Request;
use Azera\Security\GuardInterface;
use RuntimeException;

/**
 * Authenticates requests using a JSON Web Token.
 *
 * The JWT is read from the `Authorization: Bearer <token>` header. The
 * signature, expiration, and any configured claims are verified using
 * `firebase/php-jwt` (suggested dependency). When the package is not
 * installed, the guard throws on construction so the missing dependency
 * is reported at wiring time rather than at request time.
 *
 * On success the configured {@see UserProviderInterface} resolves the
 * subject (`sub` claim, or a configurable claim) to a user record.
 *
 * Refresh tokens are out of scope for the guard itself — they are an
 * application-layer concern. This guard only validates access tokens.
 */
class JwtGuard implements GuardInterface
{
    private mixed $resolvedUser = null;

    private bool $resolved = false;

    /**
     * @param Request               $request  The current HTTP request.
     * @param string                $secret   The symmetric key (HS256) or the public key (RS256).
     * @param UserProviderInterface $provider Resolves the subject claim to a user.
     * @param JwtGuardConfig|null   $config   Optional tuning knobs; defaults to a fresh {@see JwtGuardConfig}.
     */
    public function __construct(
        private Request $request,
        private string $secret,
        private UserProviderInterface $provider,
        private ?JwtGuardConfig $config = null,
    ) {
        $this->config ??= new JwtGuardConfig();

        if (!class_exists(\Firebase\JWT\JWT::class)) {
            throw new RuntimeException(
                'JwtGuard requires firebase/php-jwt. Install it with: composer require firebase/php-jwt',
            );
        }
    }

    public function name(): string
    {
        return $this->config->name;
    }

    public function attempt(array $credentials): bool
    {
        $token = (string) ($credentials['token'] ?? '');
        if ($token === '') {
            return false;
        }

        $this->dispatch(new Attempting($this->config->name, ['token' => true]));

        $user = $this->resolveFromToken($token);
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

        $token = $this->extractBearer();
        if ($token === '') {
            return null;
        }

        $user = $this->resolveFromToken($token);
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
        $this->dispatch(new Logout($this->config->name, $this->resolvedUser));
        $this->resolvedUser = null;
        $this->resolved     = true;
    }

    /**
     * Decode and verify the token, then resolve a user via the provider.
     *
     * @return mixed|null The user, or null when the token is invalid/expired.
     */
    private function resolveFromToken(string $token): mixed
    {
        try {
            $decoded = \Firebase\JWT\JWT::decode(
                $token,
                new \Firebase\JWT\Key($this->secret, $this->config->algo),
            );
        } catch (\Throwable) {
            return null;
        }

        $claims = (array) $decoded;

        foreach ($this->config->requiredClaims as $claim) {
            if (empty($claims[$claim])) {
                return null;
            }
        }

        $subject = $claims[$this->config->subjectClaim] ?? null;
        if ($subject === null) {
            return null;
        }

        return $this->provider->findById($subject);
    }

    private function extractBearer(): string
    {
        $auth = $this->request->authorization();
        if (is_array($auth) && strtolower((string) $auth['scheme']) === 'bearer') {
            return trim((string) $auth['token']);
        }

        return '';
    }

    private function dispatch(object $event): void
    {
        $this->config->dispatcher?->dispatch($event);
    }
}