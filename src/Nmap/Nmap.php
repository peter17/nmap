<?php

/**
 * This file is part of the nmap package.
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 *
 * @license    MIT License
 */

namespace Nmap;

use InvalidArgumentException;
use Nmap\Util\ProcessExecutor;
use RuntimeException;

class Nmap
{

    private $executor;

    private string $outputFile;

    private $enableOsDetection = false;

    private $enableServiceInfo = false;

    private $enableVerbose = false;

    private $disablePortScan = false;

    private $disableReverseDNS = false;

    private $treatHostsAsOnline = false;

    private $executable;

    private $timeout = 60;

    private $extraOptions = [];

    public static function create(): self
    {
        return new self();
    }

    /**
     * @throws \InvalidArgumentException
     */
    public function __construct(
        ProcessExecutor $executor = null,
        string $outputFile = null,
        string $executable = 'nmap'
    ) {
        $this->executor = $executor ?: new ProcessExecutor();
        $this->outputFile = $outputFile ?: tempnam(sys_get_temp_dir(), 'nmap-scan-output.xml');
        $this->executable = $executable;

        // If executor returns anything else than 0 (success exit code),
        // throw an exception since $executable is not executable.
        if ($this->executor->execute([$this->executable, ' -h']) !== 0) {
            throw new InvalidArgumentException(sprintf('`%s` is not executable.', $this->executable));
        }
    }

    public function setExtraOptions(array $options): self
    {
        $this->extraOptions = $options;
        return $this;
    }

    /**
     * @return array - implode with ' ' to get a command line string.
     */
    public function buildCommand(array $targets, array $ports = []): array
    {
        $options = $this->extraOptions;

        if (true === $this->enableOsDetection) {
            $options[] = '-O';
        }

        if (true === $this->enableServiceInfo) {
            $options[] = '-sV';
        }

        if (true === $this->enableVerbose) {
            $options[] = '-v';
        }

        if (true === $this->disablePortScan) {
            $options[] = '-sn';
        } elseif (!empty($ports)) {
            $options[] = '-p '.implode(',', $ports);
        }

        if ($this->disableReverseDNS) {
            $options[] = '-n';
        }

        if ($this->treatHostsAsOnline) {
            $options[] = '-Pn';
        }

        $options[] = '-oX';
        $options[] = $this->outputFile;

        return array_merge([$this->executable], $options, $targets);
    }

    /**
     * @return Host[]
     */
    public function scan(array $targets, array $ports = []): array
    {
        $command = $this->buildCommand($targets, $ports);

        $this->executor->execute($command, $this->timeout);

        if (!file_exists($this->outputFile)) {
            throw new RuntimeException(sprintf('Output file not found ("%s")', $this->outputFile));
        }

        return XmlOutputParser::parseOutputFile($this->outputFile);
    }

    public function enableOsDetection(bool $enable = true): self
    {
        $this->enableOsDetection = $enable;

        return $this;
    }

    public function enableServiceInfo(bool $enable = true): self
    {
        $this->enableServiceInfo = $enable;

        return $this;
    }

    public function enableVerbose(bool $enable = true): self
    {
        $this->enableVerbose = $enable;

        return $this;
    }

    public function disablePortScan(bool $disable = true): self
    {
        $this->disablePortScan = $disable;

        return $this;
    }

    public function disableReverseDNS(bool $disable = true): self
    {
        $this->disableReverseDNS = $disable;

        return $this;
    }

    public function treatHostsAsOnline(bool $disable = true): self
    {
        $this->treatHostsAsOnline = $disable;

        return $this;
    }

    public function setTimeout(int $timeout): self
    {
        $this->timeout = $timeout;

        return $this;
    }

    /**
     * @return \Nmap\Host[]
     */
    public function parseOutputFile(string $xmlFile)
    {
        if (!file_exists($xmlFile)) {
            throw new RuntimeException(sprintf('Output file not found ("%s")', $xmlFile));
        }

        return XmlOutputParser::parseOutputFile($xmlFile);
    }

}
