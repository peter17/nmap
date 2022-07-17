<?php

namespace Nmap\Tests;

use Symfony\Component\Filesystem\Filesystem;

abstract class TestCase extends \Mockery\Adapter\Phpunit\MockeryTestCase
{
    public Filesystem $filesystem;

    public function __construct($name = null, array $data = [], $dataName = '')
    {
        parent::__construct($name, $data, $dataName);
        $this->filesystem = new Filesystem();
    }

}
