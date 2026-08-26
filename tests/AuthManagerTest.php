<?php

declare(strict_types=1);

namespace Azera\Auth\Tests;

use Azera\Auth\AuthManager;
use Azera\Security\GuardInterface;
use InvalidArgumentException;
use PHPUnit\Framework\TestCase;
use RuntimeException;

final class AuthManagerTest extends TestCase
{
    public function test_register_and_use_default_guard(): void
    {
        $guard = $this->createStub(GuardInterface::class);
        $guard->method('check')->willReturn(true);

        $manager = new AuthManager();
        $manager->addGuard('web', $guard);

        self::assertSame('web', $manager->currentGuardName());
        self::assertTrue($manager->check());
    }

    public function test_guard_returns_named_or_current(): void
    {
        $web = $this->createStub(GuardInterface::class);
        $api = $this->createStub(GuardInterface::class);
        $api->method('id')->willReturn(42);

        $manager = new AuthManager();
        $manager->addGuard('web', $web);
        $manager->addGuard('api', $api);

        self::assertSame($web, $manager->guard());
        self::assertSame($api, $manager->guard('api'));
        self::assertSame(42, $manager->guard('api')->id());
    }

    public function test_should_use_switches_current_guard(): void
    {
        $web = $this->createStub(GuardInterface::class);
        $api = $this->createStub(GuardInterface::class);

        $manager = new AuthManager();
        $manager->addGuard('web', $web);
        $manager->addGuard('api', $api);

        $manager->shouldUse('api');
        self::assertSame('api', $manager->currentGuardName());
        self::assertSame($api, $manager->currentGuard());
    }

    public function test_unknown_guard_throws(): void
    {
        $manager = new AuthManager();

        $this->expectException(InvalidArgumentException::class);
        $manager->guard('nope');
    }

    public function test_no_guards_throws(): void
    {
        $manager = new AuthManager();

        $this->expectException(RuntimeException::class);
        $manager->currentGuard();
    }

    public function test_has_guard(): void
    {
        $guard   = $this->createStub(GuardInterface::class);
        $manager = new AuthManager();
        $manager->addGuard('web', $guard);

        self::assertTrue($manager->hasGuard('web'));
        self::assertFalse($manager->hasGuard('api'));
    }

    public function test_user_and_id_delegate_to_current_guard(): void
    {
        $guard = $this->createStub(GuardInterface::class);
        $guard->method('id')->willReturn(7);
        $guard->method('user')->willReturn(['id' => 7, 'name' => 'Ada']);

        $manager = new AuthManager();
        $manager->addGuard('web', $guard);

        self::assertSame(7, $manager->id());
        self::assertSame(['id' => 7, 'name' => 'Ada'], $manager->user());
    }

    public function test_logout_delegates(): void
    {
        $guard   = $this->createStub(GuardInterface::class);
        $manager = new AuthManager();
        $manager->addGuard('web', $guard);

        // Spy on the stub via a real guard would be ideal; here we just
        // ensure no exception propagates.
        $manager->logout();
        $this->expectNotToPerformAssertions();
    }
}