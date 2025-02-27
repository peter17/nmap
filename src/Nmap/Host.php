<?php

/**
 * This file is part of the nmap package.
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 *
 * @license    MIT License
 */

namespace Nmap;

class Host
{

    /**
     * @psalm-suppress MissingClassConstType
     */
    const STATE_UP = 'up';

    /**
     * @psalm-suppress MissingClassConstType
     */
    const STATE_DOWN = 'down';

    private array $addresses;

    private string $state;

    private array $hostnames;

    private array $ports;

    private array $scripts = [];

    private ?string $os = null;

    private ?int $os_accuracy = null;

    public function __construct(array $addresses, string $state, array $hostnames = [], array $ports = [])
    {
        $this->addresses = $addresses;
        $this->state = $state;
        $this->hostnames = $hostnames;
        $this->ports = $ports;
    }

    public function setScripts(array $scripts): void
    {
        $this->scripts = $scripts;
    }

    public function setOs(string $os): void
    {
        $this->os = $os;
    }

    public function setOsAccuracy(int $accuracy): void
    {
        $this->os_accuracy = $accuracy;
    }

    /**
     * @return Address[]
     */
    public function getAddresses(): array
    {
        return $this->addresses;
    }

    /**
     * @return Address[]
     */
    private function getAddressesByType(string $type): array
    {
        return array_filter($this->addresses, function (Address $address) use ($type) {
            return $address->getType() === $type;
        });
    }

    /**
     * @return Address[]
     */
    public function getIpv4Addresses(): array
    {
        return $this->getAddressesByType(Address::TYPE_IPV4);
    }

    /**
     * @return Address[]
     */
    public function getMacAddresses(): array
    {
        return $this->getAddressesByType(Address::TYPE_MAC);
    }

    /**
     * @return string
     */
    public function getState(): string
    {
        return $this->state;
    }

    public function getOs(): ?string
    {
        return $this->os;
    }

    public function getOsAccuracy(): ?int
    {
        return $this->os_accuracy;
    }

    /**
     * @return Hostname[]
     */
    public function getHostnames(): array
    {
        return $this->hostnames;
    }

    /**
     * @return Script[]
     */
    public function getScripts(): array
    {
        return $this->scripts;
    }

    /**
     * @return Port[]
     */
    public function getPorts(): array
    {
        return $this->ports;
    }

    /**
     * @return Port[]
     */
    public function getOpenPorts(): array
    {
        return array_filter($this->ports, function (Port $port): bool {
            return $port->isOpen();
        });
    }

    /**
     * @return Port[]
     */
    public function getClosedPorts(): array
    {
        return array_filter($this->ports, fn(Port $port) => $port->isClosed());
    }
}
