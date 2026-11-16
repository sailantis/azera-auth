# Changelog

All notable changes to `sailantis/azera-auth` are documented here.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.4.2] - 2026-11-16

First tagged release. Version numbers follow `sailantis/azera-framework`.

### Added

- Guards: `SessionGuard`, `TokenGuard`, `JwtGuard`, `OAuth2Guard`.
- User providers via `UserProviderInterface`, plus `CallbackUserProvider`.
- Authorization: `Gate`, `Authorizable`, `AuthorizableTrait`.
- Password reset (`PasswordBroker`, token repositories) and email verification.
- Two-factor authentication (TOTP) with optional QR rendering.

### Notes

`firebase/php-jwt`, `league/oauth2-client`, `spomky-labs/otphp` and
`bacon/bacon-qr-code` are declared as `suggest` entries: install only the one
your chosen guard or authenticator needs.
