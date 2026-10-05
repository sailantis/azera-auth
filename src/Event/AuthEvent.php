<?php

declare(strict_types=1);

namespace Azera\Auth\Event;

/**
 * Base for authentication lifecycle events.
 *
 * All auth events are value objects: readonly properties set in the
 * constructor. They are dispatched through the PSR-14
 * {@see \Psr\EventDispatcher\EventDispatcherInterface} (the framework's
 * `AppContext::events()`), mirroring the DB event pattern in
 * `Azera\Db\Event\*`.
 *
 * A listener for auth events can be registered with the dispatcher:
 *
 * ```php
 * $dispatcher->listen(Login::class, function (Login $event) use ($ctx) {
 *     $ctx->logger()->info('User logged in', ['id' => $event->userId]);
 * });
 * ```
 */
abstract class AuthEvent
{
}