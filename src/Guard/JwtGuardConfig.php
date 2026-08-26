<?php

declare(strict_types=1);

namespace Azera\Auth\Guard;

use Psr\EventDispatcher\EventDispatcherInterface;

/**
 * Immutable configuration for {@see JwtGuard}.
 *
 * Groups the optional tuning knobs of the guard into a single value
 * object so the guard's constructor stays focused on its required
 * dependencies. Construct with named arguments to override only the
 * settings you care about; everything else falls back to the defaults.
 */
final class JwtGuardConfig
{
    /**
     * @param string                        $name            Guard name (for events).
     * @param string                        $algo            Expected algorithm, e.g. 'HS256'.
     * @param EventDispatcherInterface|null  $dispatcher      Optional PSR-14 dispatcher.
     * @param string                        $subjectClaim    Claim carrying the user identifier (default `sub`).
     * @param array<string, mixed>          $requiredClaims  Claim names that must be present and non-empty.
     */
    public function __construct(
        public string $name = 'jwt',
        public string $algo = 'HS256',
        public ?EventDispatcherInterface $dispatcher = null,
        public string $subjectClaim = 'sub',
        public array $requiredClaims = [],
    ) {}
}