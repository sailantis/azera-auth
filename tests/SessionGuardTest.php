<?php

declare(strict_types=1);

namespace Azera\Auth\Tests;

use Azera\Auth\Guard\SessionGuard;
use Azera\Auth\Provider\CallbackUserProvider;
use Azera\Auth\Provider\UserProviderInterface;
use Azera\Http\Session;
use Azera\Security\Hasher;
use PHPUnit\Framework\TestCase;

final class SessionGuardTest extends TestCase
{
    private function session(): Session
    {
        $store = [];
        return new Session($store);
    }

    private function userProvider(string $email, string $hash): UserProviderInterface
    {
        return new CallbackUserProvider(
            findByCredentials: fn(array $c) =>
                ($c['email'] ?? '') === $email ? ['id' => 1, 'email' => $email, 'password_hash' => $hash] : null,
            findById: fn($id) =>
                $id === 1 ? ['id' => 1, 'email' => $email, 'password_hash' => $hash] : null,
        );
    }

    public function test_attempt_success_persists_session(): void
    {
        $hasher  = new Hasher();
        $hash    = $hasher->make('secret');
        $session = $this->session();
        $guard   = new SessionGuard(
            provider: $this->userProvider('ada@example.com', $hash),
            session: $session,
            hasher: $hasher,
        );

        self::assertTrue($guard->attempt(['email' => 'ada@example.com', 'password' => 'secret']));
        self::assertTrue($guard->check());
        self::assertSame(1, $guard->id());
    }

    public function test_attempt_failure_does_not_persist(): void
    {
        $hasher = new Hasher();
        $guard  = new SessionGuard(
            provider: $this->userProvider('ada@example.com', $hasher->make('secret')),
            session: $this->session(),
            hasher: $hasher,
        );

        self::assertFalse($guard->attempt(['email' => 'ada@example.com', 'password' => 'wrong']));
        self::assertFalse($guard->check());
        self::assertNull($guard->id());
    }

    public function test_attempt_with_unknown_user_fails(): void
    {
        $guard = new SessionGuard(
            provider: new CallbackUserProvider(
                findByCredentials: fn() => null,
                findById: fn() => null,
            ),
            session: $this->session(),
            hasher: new Hasher(),
        );

        self::assertFalse($guard->attempt(['email' => 'nope@example.com', 'password' => 'x']));
        self::assertFalse($guard->check());
    }

    public function test_logout_clears_session(): void
    {
        $hasher  = new Hasher();
        $hash    = $hasher->make('secret');
        $session = $this->session();
        $guard   = new SessionGuard(
            provider: $this->userProvider('ada@example.com', $hash),
            session: $session,
            hasher: $hasher,
        );

        $guard->attempt(['email' => 'ada@example.com', 'password' => 'secret']);
        self::assertTrue($guard->check());

        $guard->logout();
        self::assertFalse($guard->check());
        self::assertNull($guard->id());
    }

    public function test_login_bypasses_credentials(): void
    {
        $guard = new SessionGuard(
            provider: new CallbackUserProvider(
                findByCredentials: fn() => null,
                findById: fn($id) => ['id' => $id, 'email' => 'ada@example.com'],
            ),
            session: $this->session(),
            hasher: new Hasher(),
        );

        $guard->login(['id' => 9, 'email' => 'ada@example.com']);
        self::assertSame(9, $guard->id());
        self::assertSame('ada@example.com', $guard->user()['email']);
    }
}