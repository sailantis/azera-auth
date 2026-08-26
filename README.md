# azera-auth

Authentication companion for the [Azera framework](../azera-framework).

The framework ships authentication **contracts** (`Azera\Security\AuthManagerInterface`, `Azera\Security\GuardInterface`) plus primitives (`Hasher`, `RateLimiter`, `CsrfMiddleware`). This package provides the **implementations** the docs defer to the companion:

- `Azera\Auth\AuthManager` — the `AuthManagerInterface` implementation; a named-guard registry with current-guard tracking.
- Guards: `SessionGuard`, `TokenGuard`, `JwtGuard` (optional), `OAuth2Guard` (optional).
- User providers: `UserProviderInterface` + `DbUserProvider` — decouples guards from how users are loaded.
- Middleware: `AuthMiddleware` — resolves the current user per request, 401s when auth is required.
- Password reset: `PasswordBroker` + `DbTokenRepository`.
- Email verification: `EmailVerification`.
- Authorization: `Authorizable` trait + `Gate` (roles & abilities).
- Two-factor: `TwoFactorAuthenticator` (TOTP + QR + backup codes; extracted from the Sailantis homepage).
- Events: PSR-14 `Attempting`, `Authenticated`, `Login`, `Failed`, `Lockout`, `Logout`, `PasswordResetRequested`, `Verified`.

## Installation

Add the path repository and require the package in your app's `composer.json`:

```json
{
    "repositories": [
        { "type": "path", "url": "../azera-auth" }
    ],
    "require": {
        "sailantis/azera-auth": "dev-main"
    }
}
```

Optional features pull their dependencies via Composer `suggest`:

| Feature | Suggested package |
|---|---|
| `JwtGuard` | `firebase/php-jwt` |
| `OAuth2Guard` | `league/oauth2-client` |
| `TwoFactorAuthenticator` (TOTP) | `spomky-labs/otphp` |
| `TwoFactorAuthenticator` (QR) | `bacon/bacon-qr-code` |

## Wiring

```php
use Azera\Auth\AuthManager;
use Azera\Auth\Guard\SessionGuard;
use Azera\Auth\Guard\SessionGuardConfig;
use Azera\Auth\Provider\DbUserProvider;
use Azera\Security\AuthManagerInterface;
use Azera\Security\Hasher;

$manager = new AuthManager();
$manager->addGuard('web', new SessionGuard(
    provider: new DbUserProvider(/* ... */),
    session: $ctx->session(),
    hasher: new Hasher(),
    config: new SessionGuardConfig(
        rateLimiter: $ctx->get(RateLimiter::class),
        cookies: $ctx->cookies(),
    ),
));

$ctx->set(AuthManagerInterface::class, $manager);
```

See the [plan](../azera-framework/docs/18-SECURITY-ENTERPRISE.md) and each class for details.

## License

MIT.