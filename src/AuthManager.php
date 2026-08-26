<?php

declare(strict_types=1);

namespace Azera\Auth;

use Azera\Security\AuthManagerInterface;
use Azera\Security\GuardInterface;
use InvalidArgumentException;
use RuntimeException;

/**
 * Registry of named authentication guards.
 *
 * The default implementation of {@see AuthManagerInterface}. It owns the
 * currently active guard and delegates {@see attempt()}/{@see logout()}/
 * {@see check()}/{@see id()} to it. Switch the active guard with
 * {@see shouldUse()} when entering a scope that needs a different
 * authentication strategy (e.g. an API controller using the "api" guard).
 *
 * The framework deliberately ships only the contract; this companion
 * provides the concrete manager.
 */
class AuthManager implements AuthManagerInterface
{
    /** @var array<string, GuardInterface> */
    private array $guards = [];

    private ?string $currentName = null;

    /**
     * Register a guard under a name.
     *
     * @param string         $name  Guard identifier (e.g. "web", "api").
     * @param GuardInterface $guard The guard instance.
     */
    public function addGuard(string $name, GuardInterface $guard): void
    {
        $this->guards[$name] = $guard;

        if ($this->currentName === null) {
            $this->currentName = $name;
        }
    }

    /**
     * Get a guard by name, or the current guard when $name is null.
     *
     * @param string|null $name Guard identifier previously registered.
     * @return GuardInterface
     * @throws InvalidArgumentException If no guard is registered under $name.
     */
    public function guard(?string $name = null): GuardInterface
    {
        $name ??= $this->currentName;

        if ($name === null) {
            throw new RuntimeException('No authentication guards have been registered.');
        }

        if (!isset($this->guards[$name])) {
            throw new InvalidArgumentException(sprintf('No guard registered under "%s".', $name));
        }

        return $this->guards[$name];
    }

    /**
     * Switch the currently active guard and return it.
     *
     * @param string $name Guard identifier previously registered.
     * @return GuardInterface
     * @throws InvalidArgumentException If no guard is registered under $name.
     */
    public function shouldUse(string $name): GuardInterface
    {
        if (!isset($this->guards[$name])) {
            throw new InvalidArgumentException(sprintf('No guard registered under "%s".', $name));
        }

        $this->currentName = $name;

        return $this->guards[$name];
    }

    /**
     * Get the currently active guard.
     *
     * @return GuardInterface
     * @throws RuntimeException If no guards have been registered.
     */
    public function currentGuard(): GuardInterface
    {
        if ($this->currentName === null) {
            throw new RuntimeException('No authentication guards have been registered.');
        }

        return $this->guards[$this->currentName];
    }

    /**
     * Get the name of the currently active guard, or null when none
     * has been set.
     */
    public function currentGuardName(): ?string
    {
        return $this->currentName;
    }

    /**
     * Whether a guard has been registered under $name.
     */
    public function hasGuard(string $name): bool
    {
        return isset($this->guards[$name]);
    }

    public function attempt(array $credentials): bool
    {
        return $this->currentGuard()->attempt($credentials);
    }

    public function logout(): void
    {
        $this->currentGuard()->logout();
    }

    public function check(): bool
    {
        return $this->currentGuard()->check();
    }

    public function id(): mixed
    {
        return $this->currentGuard()->id();
    }

    /**
     * Get the authenticated user via the current guard.
     */
    public function user(): mixed
    {
        return $this->currentGuard()->user();
    }
}