<?php

declare(strict_types=1);

namespace Azera\Auth\Guard;

use Azera\Http\Cookies;
use Azera\Security\RateLimiter;
use Closure;
use Psr\EventDispatcher\EventDispatcherInterface;

/**
 * Immutable configuration for {@see SessionGuard}.
 *
 * Groups the optional tuning knobs of the guard into a single value
 * object so the guard's constructor stays focused on its required
 * dependencies. Construct with named arguments to override only the
 * settings you care about; everything else falls back to the defaults.
 */
final class SessionGuardConfig
{
    /**
     * @param string                          $name             Guard name (for events).
     * @param EventDispatcherInterface|null   $dispatcher       Optional PSR-14 dispatcher.
     * @param RateLimiter|null                $rateLimiter      Optional login throttle.
     * @param string                          $rateLimitKey     Rate-limit key prefix (the email is appended).
     * @param int                             $maxAttempts      Max attempts per window.
     * @param int                             $decaySeconds     Throttle window length.
     * @param Cookies|null                    $cookies          Cookie jar for "remember me".
     * @param Closure|null                    $identifier       fn(array $credentials): string  extracts the identifier (defaults to email).
     * @param string                          $passwordField    Credential key holding the password.
     * @param int                             $rememberMinutes  Lifetime of the "remember me" cookie.
     */
    public function __construct(
        public string $name = 'web',
        public ?EventDispatcherInterface $dispatcher = null,
        public ?RateLimiter $rateLimiter = null,
        public string $rateLimitKey = 'login:',
        public int $maxAttempts = 5,
        public int $decaySeconds = 60,
        public ?Cookies $cookies = null,
        public ?Closure $identifier = null,
        public string $passwordField = 'password',
        public int $rememberMinutes = 60 * 24 * 30,
    ) {}
}