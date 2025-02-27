<?php

/**
 * This file is part of the nmap package.
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 *
 * @license    MIT License
 */

namespace Nmap;

class Address
{
    /**
     * @psalm-suppress MissingClassConstType
     */
    const TYPE_IPV4 = 'ipv4';
    /**
     * @psalm-suppress MissingClassConstType
     */
    const TYPE_MAC = 'mac';

    private string $address;

    private string $type;

    private string $vendor;

    public function __construct(string $address, string $type = self::TYPE_IPV4, string $vendor = '')
    {
        $this->address = $address;
        $this->type = $type;
        $this->vendor = $vendor;
    }

    public function getAddress(): string
    {
        return $this->address;
    }

    public function getType(): string
    {
        return $this->type;
    }

    public function getVendor(): string
    {
        return $this->vendor;
    }
}
