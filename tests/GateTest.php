<?php

declare(strict_types=1);

namespace Azera\Auth\Tests;

use Azera\Auth\Authorization\AuthorizationException;
use Azera\Auth\Authorization\Authorizable;
use Azera\Auth\Authorization\AuthorizableTrait;
use Azera\Auth\Authorization\Gate;
use PHPUnit\Framework\TestCase;

final class GateTest extends TestCase
{
    public function test_define_and_allows(): void
    {
        $gate = new Gate();
        $gate->define('admin', fn($user) => $user === 'admin');

        self::assertTrue($gate->allows('admin', 'admin'));
        self::assertFalse($gate->allows('admin', 'guest'));
    }

    public function test_before_short_circuits(): void
    {
        $gate = new Gate();
        $gate->before(fn($user, $ability) => $user === 'super' ? true : null);
        $gate->define('edit', fn($user) => false);

        self::assertTrue($gate->allows('edit', 'super'));
        self::assertFalse($gate->allows('edit', 'other'));
    }

    public function test_falls_back_to_authorizable(): void
    {
        $user = new class implements Authorizable
        {
            use AuthorizableTrait;
            public function roles(): array
            {
                return ['admin'];
            }
            public function permissions(): array
            {
                return ['billing.manage'];
            }
        };

        $gate = new Gate();
        self::assertTrue($gate->allows('billing.manage', $user));
        self::assertFalse($gate->allows('unknown', $user));
    }

    public function test_authorize_throws_on_denial(): void
    {
        $gate = new Gate();
        $gate->define('edit', fn($user) => false);

        $this->expectException(AuthorizationException::class);
        $gate->authorize('edit', 'guest');
    }

    public function test_denies_and_has(): void
    {
        $gate = new Gate();
        $gate->define('edit', fn($user) => $user === 'admin');

        self::assertTrue($gate->denies('edit', 'guest'));
        self::assertTrue($gate->has('edit'));
        self::assertFalse($gate->has('missing'));
    }
}