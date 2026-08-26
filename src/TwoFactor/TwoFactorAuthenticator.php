<?php

declare(strict_types=1);

namespace Azera\Auth\TwoFactor;

use RuntimeException;
use function hash_equals;
use function time;

/**
 * Two-factor authentication helper using TOTP (RFC 6238).
 *
 * Extracted and generalized from the Sailantis homepage
 * (`App\Controllers\PhpThunder\AccountController` /
 * `App\Services\PhpThunderAccountService`), which previously inlined
 * TOTP setup/activation and QR rendering directly in the controller.
 *
 * This class wraps `spomky-labs/otphp` (TOTP) and `bacon/bacon-qr-code`
 * (QR SVG) behind a single API so every Azera application gets TOTP
 * enroll, verify, backup codes, and QR rendering without re-implementing
 * it. Both packages are `suggest` dependencies; the class throws on
 * construction when the required library is missing so the missing
 * dependency is reported at wiring time.
 *
 * The secret is generated per-user and stored by the application
 * (typically encrypted at rest). This class never persists anything —
 * it is a pure crypto/rendering helper.
 *
 * Example:
 * <code>
 * $tfa = new TwoFactorAuthenticator();
 * $secret = $tfa->generateSecret();
 * $uri    = $tfa->provisioningUri('user@example.com', 'Sailantis', $secret);
 * $qrSvg  = $tfa->qrSvg($uri, 200);
 * // ... later, on activation:
 * if ($tfa->verify($code, $secret)) { /* mark 2FA active *\/ }
 * </code>
 */
class TwoFactorAuthenticator
{
    /**
     * @param int $digits Number of TOTP digits (6 or 8). Defaults to 6.
     * @param int $period TOTP period in seconds. Defaults to 30.
     */
    public function __construct(
        private int $digits = 6,
        private int $period = 30,
    ) {
        if (!class_exists(\Otp\Otp::class) && !class_exists(\OTPHP\OTP::class) && !class_exists(\OTPHP\TOTP::class)) {
            throw new RuntimeException(
                'TwoFactorAuthenticator requires spomky-labs/otphp. Install it with: composer require spomky-labs/otphp',
            );
        }
    }

    /**
     * Generate a fresh base32-encoded TOTP secret.
     */
    public function generateSecret(int $length = 32): string
    {
        return $this->totpFactory($length)->getSecret();
    }

    /**
     * Build the `otpauth://` provisioning URI for authenticator apps.
     *
     * @param string $account  Account label (e.g. the user's email).
     * @param string $issuer   Issuer name shown in the app (e.g. 'Sailantis').
     * @param string $secret   The base32 secret.
     */
    public function provisioningUri(string $account, string $issuer, string $secret): string
    {
        $totp = $this->totpFactory(0, $secret);
        $totp->setLabel($account);
        $totp->setIssuer($issuer);

        return $totp->getProvisioningUri();
    }

    /**
     * Verify a TOTP code against the secret.
     *
     * @param string    $code    The 6/8-digit code from the authenticator app.
     * @param string    $secret  The base32 secret stored for the user.
     * @param int|null  $window  Allowed clock drift in periods (default 1, ±30s).
     * @param int|null  $timestamp The verification time (default now).
     */
    public function verify(string $code, string $secret, ?int $window = 1, ?int $timestamp = null): bool
    {
        if ($code === '' || $secret === '') {
            return false;
        }

        $totp = $this->totpFactory(0, $secret);
        $totp->setDigits($this->digits);
        $totp->setPeriod($this->period);

        $timestamp ??= time();

        return $totp->verify($code, $timestamp, $window);
    }

    /**
     * Generate a set of one-time backup codes.
     *
     * @param int $count Number of backup codes to generate (default 10).
     * @return string[] Array of hex-encoded backup codes.
     */
    public function generateBackupCodes(int $count = 10): array
    {
        $codes = [];
        for ($i = 0; $i < $count; $i++) {
            // 8 chars (4 bytes) of alphanumeric, no ambiguous chars.
            $alphabet = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789';
            $bytes    = random_bytes(4);
            $code     = '';
            for ($j = 0; $j < 8; $j++) {
                $code .= $alphabet[ord($bytes[$j % 4]) % strlen($alphabet)];
            }
            $codes[] = $code;
        }

        return $codes;
    }

    /**
     * Verify a backup code against a stored list.
     *
     * The supplied list is mutated in place: the matched code is removed
     * so it cannot be reused. Comparison is constant-time per entry.
     *
     * @param string[]  $stored  The user's currently valid backup codes (by reference).
     * @param string    $code    The code supplied by the user.
     * @return bool True when the code matched and was consumed.
     */
    public function verifyBackupCode(array &$stored, string $code): bool
    {
        if ($code === '') {
            return false;
        }

        foreach ($stored as $i => $candidate) {
            if (hash_equals($candidate, $code)) {
                unset($stored[$i]);
                return true;
            }
        }

        return false;
    }

    /**
     * Render the provisioning URI as an inline SVG QR code.
     *
     * @param string $provisioningUri The URI from {@see provisioningUri()}.
     * @param int    $size            Square size in pixels (default 200).
     * @return string The SVG markup.
     * @throws RuntimeException When bacon/bacon-qr-code is not installed.
     */
    public function qrSvg(string $provisioningUri, int $size = 200): string
    {
        if (!class_exists(\BaconQrCode\Renderer\Image\SvgImageBackEnd::class)) {
            throw new RuntimeException(
                'QR rendering requires bacon/bacon-qr-code. Install it with: composer require bacon/bacon-qr-code',
            );
        }

        $renderer = new \BaconQrCode\Renderer\ImageRenderer(
            new \BaconQrCode\Renderer\RendererStyle\RendererStyle($size),
            new \BaconQrCode\Renderer\Image\SvgImageBackEnd(),
        );

        return (new \BaconQrCode\Writer($renderer))->writeString($provisioningUri);
    }

    /**
     * Construct a configured TOTP object, supporting both the
     * spomky-labs/otphp v11 (`OTPHP\TOTP`) and v10 (`Otp\Otp`) APIs.
     *
     * @param int    $secretLength Used only on generation; 0 means reuse the supplied secret.
     * @param string $secret       The base32 secret (when not generating a new one).
     */
    private function totpFactory(int $secretLength = 0, string $secret = ''): mixed
    {
        if (class_exists(\OTPHP\TOTP::class)) {
            $totp = \OTPHP\TOTP::generate($secretLength > 0 ? $secretLength : 32);
            if ($secret !== '') {
                $totp = \OTPHP\TOTP::createFromSecret($secret);
            }
            $totp->setDigits($this->digits);
            $totp->setPeriod($this->period);
            return $totp;
        }

        // Fallback: older spomky-labs/otphp API
        if (class_exists(\Otp\Otp::class)) {
            $otp = new \Otp\Otp();
            $otp->setLabel('azera');
            if ($secret !== '') {
                $otp->setSecret($secret);
            } else {
                $otp->setSecret(\Otp\Otp::generateRandomSecret($secretLength > 0 ? $secretLength : 32));
            }
            return $otp;
        }

        throw new RuntimeException('No supported TOTP library is installed.');
    }
}