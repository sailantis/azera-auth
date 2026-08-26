<?php

declare(strict_types=1);

namespace Azera\Auth\Guard;

use Psr\EventDispatcher\EventDispatcherInterface;

/**
 * Immutable configuration for {@see TokenGuard}.
 *
 * Groups the optional tuning knobs of the guard into a single value
 * object so the guard's constructor stays focused on its required
 * dependencies. Construct with named arguments to override only the
 * settings you care about; everything else falls back to the defaults.
 */
final class TokenGuardConfig
{
    /**
     * @param string                        $name        Guard name (for events).
     * @param EventDispatcherInterface|null  $dispatcher  Optional PSR-14 dispatcher.
     * @param string                         $header      Alternate header name (default `X-API-Key`).
     * @param string                         $queryParam  Query-string parameter name (default `_api_key`).
     * @param callable|null                  $onLogout   fn(string $token): void  to revoke the token on logout.
     */
    public function __construct(
        public string $name = 'api',
        public ?EventDispatcherInterface $dispatcher = null,
        public string $header = 'X-API-Key',
        public string $queryParam = '_api_key',
        public $onLogout = null,
    ) {}
}