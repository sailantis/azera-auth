<?php

declare(strict_types=1);

namespace Azera\Auth\Attribute;

use Attribute;

/**
 * Marks a controller action (or a controller class) as requiring an
 * authenticated user.
 *
 * When attached to a route, the {@see \Azera\Auth\Middleware\AuthMiddleware}
 * (configured to read this attribute) will reject unauthenticated requests
 * with a 401 before the action runs. Optionally restrict access to one
 * or more roles (checked via the framework's authorization gate).
 *
 * Example:
 * <code>
 * #[RequiresAuth]
 * public function dashboardAction(): string { ... }
 *
 * #[RequiresAuth(roles: ['admin'])]
 * public function adminAction(): string { ... }
 * </code>
 */
#[Attribute(Attribute::TARGET_METHOD | Attribute::TARGET_CLASS)]
class RequiresAuth
{
    /**
     * @param string[]|null $roles Optional role allowlist. When set, the
     *   user must hold at least one of the listed roles (checked via
     *   {@see \Azera\Auth\Authorization\Gate}).
     */
    public function __construct(
        public readonly ?array $roles = null,
    ) {}
}