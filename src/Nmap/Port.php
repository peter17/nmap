<?php

/**
 * This file is part of the nmap package.
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 *
 * @license    MIT License
 */

namespace Nmap;

class Port
{
    /**
     * @psalm-suppress MissingClassConstType
     */
    const STATE_OPEN = 'open';
    /**
     * @psalm-suppress MissingClassConstType
     */
    const STATE_CLOSED = 'closed';

    private int $number;

    private string $protocol;

    private string $state;

    private Service $service;

    private array $scripts = [];

    public function __construct(int $number, string $protocol, string $state, Service $service)
    {
        $this->number = $number;
        $this->protocol = $protocol;
        $this->state = $state;
        $this->service = $service;
    }

    public function setScripts(array $scripts): void
    {
        $this->scripts = $scripts;
    }

    public function getNumber(): int
    {
        return $this->number;
    }

    public function getProtocol(): string
    {
        return $this->protocol;
    }

    /**
     * @return string one of self::STATE_OPEN or STATE_CLOSED
     */
    public function getState(): string
    {
        return $this->state;
    }

    public function isOpen(): bool
    {
        return self::STATE_OPEN === $this->state;
    }

    public function isClosed(): bool
    {
        return self::STATE_CLOSED === $this->state;
    }

    public function getService(): Service
    {
        return $this->service;
    }

    /**
     * @return Script[]
     */
    public function getScripts(): array
    {
        return $this->scripts;
    }
}
