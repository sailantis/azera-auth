<?php

declare(strict_types=1);

namespace Azera\Auth\Tests;

use Azera\Auth\Verification\EmailVerification;
use PHPUnit\Framework\TestCase;

final class EmailVerificationTest extends TestCase
{
    public function test_create_and_verify_round_trip(): void
    {
        $verifier = new EmailVerification('super-secret');
        $token    = $verifier->createToken(['id' => '42']);

        $resolved = null;
        $marked   = false;
        $ok       = $verifier->verify($token, function ($id) use (&$resolved) {
            $resolved = $id;
            return ['id' => $id];
        }, function ($user) use (&$marked) {
            $marked = true;
        });

        self::assertTrue($ok);
        self::assertSame('42', $resolved);
        self::assertTrue($marked);
    }

    public function test_verify_rejects_tampered_token(): void
    {
        $verifier = new EmailVerification('super-secret');
        $token    = $verifier->createToken(['id' => '42']);
        $tampered = substr($token, 0, -2) . 'xx';

        self::assertFalse($verifier->verify($tampered, fn() => ['id' => 42], fn() => null));
    }

    public function test_verify_rejects_wrong_secret(): void
    {
        $issuer = new EmailVerification('secret-a');
        $token  = $issuer->createToken(['id' => '1']);

        $verifier = new EmailVerification('secret-b');
        self::assertFalse($verifier->verify($token, fn() => ['id' => 1], fn() => null));
    }

    public function test_verify_rejects_expired_token(): void
    {
        $verifier = new EmailVerification('s', expires: -1);
        $token    = $verifier->createToken(['id' => '1']);

        self::assertFalse($verifier->verify($token, fn() => ['id' => 1], fn() => null));
    }
}