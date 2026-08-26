<?php

declare(strict_types=1);

namespace Azera\Auth\Authorization;

use RuntimeException;

/**
 * Thrown when an authorization check fails.
 *
 * The {@see \Azera\Auth\Authorization\Gate} and the {@see Authorizable}
 * trait throw this when an ability or role is denied. The AOP
 * `#[Authorize]` interceptor (companion package) surfaces it as a 403.
 */
class AuthorizationException extends RuntimeException
{
}