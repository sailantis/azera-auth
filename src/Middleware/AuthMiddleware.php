<?php

declare(strict_types=1);

namespace Azera\Auth\Middleware;

use Azera\AppContext;
use Azera\Core\MiddlewareInterface;
use Azera\Http\Response;
use Azera\Security\AuthManagerInterface;

/**
 * Resolves the authenticated user on every request and rejects requests
 * that require authentication when no user is present.
 *
 * Routes opt into authentication via the {@see \Azera\Auth\Attribute\RequiresAuth}
 * attribute (or a configurable flag in the route metadata). When the
 * attribute is present and no user is authenticated, a 401 JSON response
 * is returned. Routes without the attribute are unaffected.
 *
 * The middleware itself never inspects the route; it depends on the
 * dispatcher to set a flag in the AppContext (or on the resolved route)
 * indicating that the current route requires auth. The flag is read via
 * the supplied callable so this class stays decoupled from the router.
 */
class AuthMiddleware implements MiddlewareInterface
{
    /**
     * @param AuthManagerInterface $auth      The auth manager (resolved from the container when null).
     * @param callable              $requires  fn(AppContext): bool  returns true when the current route requires auth.
     * @param callable|null         $onUnauth  fn(AppContext): ?Response  custom 401 response builder (defaults to JSON 401).
     */
    public function __construct(
        private ?AuthManagerInterface $auth = null,
        private $requires = null,
        private $onUnauth = null,
    ) {}

    public function process(AppContext $context, callable $next): ?Response
    {
        $auth = $this->auth ?? $context->get(AuthManagerInterface::class);

        if ($auth !== null) {
            // Eagerly resolve the user so controllers can call check()/user() cheaply.
            $auth->currentGuard()->user();
        }

        $requires = $this->requires !== null
            ? (bool) ($this->requires)($context)
            : false;

        if ($requires && ($auth === null || !$auth->check())) {
            return $this->unauthorized($context);
        }

        return $next($context);
    }

    private function unauthorized(AppContext $context): Response
    {
        if ($this->onUnauth !== null) {
            $response = ($this->onUnauth)($context);
            if ($response instanceof Response) {
                return $response;
            }
        }

        return Response::json(['error' => 'Unauthenticated.'], 401);
    }
}