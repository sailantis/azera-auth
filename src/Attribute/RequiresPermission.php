<?php

declare(strict_types=1);

namespace Azera\Auth\Attribute;

use Attribute;

/**
 * Marks a controller action as requiring the authenticated user to hold
 * a specific permission/ability.
 *
 * Checked via the framework's {@see \Azera\Auth\Authorization\Gate} (or
 * any `Authorizable` user). When the user lacks the ability, the route
 * is rejected with a 403.
 *
 * Example:
 * <code>
 * #[RequiresPermission('billing.manage')]
 * public function invoicesAction(): string { ... }
 * </code>
 */
#[Attribute(Attribute::TARGET_METHOD | Attribute::TARGET_CLASS)]
class RequiresPermission
{
    public function __construct(
        public readonly string $ability,
        public readonly mixed $arguments = null,
    ) {}
}