<?php

declare(strict_types=1);

namespace Azera\Auth\Tests;

use Azera\Auth\Password\ArrayTokenRepository;
use Azera\Auth\Password\PasswordBroker;
use Azera\Security\Hasher;
use PHPUnit\Framework\TestCase;

final class PasswordBrokerTest extends TestCase
{
    public function test_send_reset_link_creates_token(): void
    {
        $repo   = new ArrayTokenRepository();
        $broker = new PasswordBroker($repo);

        $result = $broker->sendResetLink(['email' => 'ada@example.com'], fn($c) => ['id' => 1, 'email' => $c['email']]);

        self::assertTrue($result);
    }

    public function test_send_reset_link_returns_false_for_unknown_user(): void
    {
        $broker = new PasswordBroker(new ArrayTokenRepository());

        self::assertFalse($broker->sendResetLink(['email' => 'nope'], fn() => null));
    }

    public function test_reset_with_valid_token_updates_password(): void
    {
        $repo   = new ArrayTokenRepository();
        $broker = new PasswordBroker($repo, new Hasher());
        $user   = ['id' => 1, 'email' => 'ada@example.com'];

        $token = '';
        $broker->sendResetLink(['email' => 'ada@example.com'], fn() => $user);

        // Capture the token from the repository's internals by re-creating.
        // Use a second broker + token to validate the round-trip directly.
        $token = $repo->create($user, 3600);

        $saved = '';
        $ok    = $broker->reset($user, $token, 'new-password', function ($u, $hash) use (&$saved) {
            $saved = $hash;
        });

        self::assertTrue($ok);
        self::assertNotEmpty($saved);
        self::assertTrue((new Hasher())->verify('new-password', $saved));
    }

    public function test_reset_with_invalid_token_fails(): void
    {
        $broker = new PasswordBroker(new ArrayTokenRepository());

        $ok = $broker->reset(['id' => 1], 'bad-token', 'pw', fn() => null);
        self::assertFalse($ok);
    }
}