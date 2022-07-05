<?php

namespace Nmap;

use SimpleXMLElement;
use Symfony\Component\Filesystem\Exception\FileNotFoundException;
use Symfony\Component\Process\Exception\RuntimeException;
use Symfony\Component\Process\ExecutableFinder;
use Symfony\Component\Process\Process;
use Symfony\Component\Filesystem\Filesystem;

class XmlOutputParser
{

    protected Filesystem $filesystem;

    protected string $xmlFile;

    public function __construct(string $xmlFile)
    {
        $filesystem = new Filesystem();
        if (! $filesystem->exists($xmlFile)) {
            throw new FileNotFoundException($xmlFile);
        }
        $this->filesystem = $filesystem;
        $this->xmlFile = $xmlFile;
    }

    /**
     * Check if DTD is present under default install path. If not attempt to download
     * the most recent.
     *
     * @link https://nmap.org/book/app-nmap-dtd.html
     */
    private function getDtd($dtdPath = ''): string
    {
        $dtdPath = empty($dtdPath) ? '/usr/share/nmap/nmap.dtd' : $dtdPath;
        if ($this->filesystem->exists($dtdPath)) {
            return $dtdPath;
        }

        // Download official Nmap DTD
        $dtdPath = '/tmp/nmap.dtd';
        if ($this->filesystem->exists($dtdPath)) {
            return $dtdPath;
        }

        $this->filesystem->dumpFile($dtdPath, 'https://svn.nmap.org/nmap/docs/nmap.dtd');
        return $dtdPath;
    }

    /**
     * DTD Validation is done using xmlstarlet because this is very cumbersome using standard PHP.
     * Besides validation xmlstarlet contains other useful features for future development.
     *
     * @link http://xmlstar.sourceforge.net/
     */
    private function getXmlstarlet(): string
    {
        $xmlstarlet = (new ExecutableFinder)->find('xmlstarlet');
        if (empty($xmlstarlet)) {
            throw new RuntimeException('xmlstarlet could not be found');
        }
        return $xmlstarlet;
    }

    /**
     * Validate output file using DTD as recommended by Nmap.
     *
     * @link http://xmlstar.sourceforge.net/doc/UG/ch04s04.html
     * @return bool|string true if valid, an error string if invalid
     */
    public function validate($dtdPath = null): bool|string
    {
        $process = new Process([
            $this->getXmlstarlet(),
            'val',
            '-e',
            '--dtd', $this->getDtd($dtdPath),
            $this->xmlFile
        ]);
        $process->setTimeout(900);
        $process->run();

        $error = $process->getErrorOutput();
        return empty($error) ? true : $error;
    }

    /**
     * @return Host[]
     */
    public function parse(): array
    {
        $xml = simplexml_load_file($this->xmlFile);

        $hosts = [];
        foreach ($xml->host as $xmlHost) {
            $host = new Host(
                self::parseAddresses($xmlHost),
                (string) $xmlHost->status->attributes()->state,
                isset($xmlHost->hostnames) ? self::parseHostnames($xmlHost->hostnames->hostname) : [],
                isset($xmlHost->ports) ? self::parsePorts($xmlHost->ports->port) : []
            );
            if (isset($xmlHost->hostscript)) {
                $host->setScripts(self::parseScripts($xmlHost->hostscript->script));
            }
            if (isset($xmlHost->os->osmatch)) {
                $host->setOs((string) $xmlHost->os->osmatch->attributes()->name);
                $host->setOsAccuracy((int) $xmlHost->os->osmatch->attributes()->accuracy);
            }
            $hosts[] = $host;
        }

        return $hosts;
    }

    /**
     * @return Hostname[]
     */
    public static function parseHostnames(SimpleXMLElement $xmlHostnames): array
    {
        $hostnames = [];
        foreach ($xmlHostnames as $hostname) {
            $attrs = $hostname->attributes();
            $name = $type = null;
            if (!is_null($attrs)) {
                $name = $attrs->name;
                $type = $attrs->type;
            }

            if (!is_null($name) && !is_null($type)) {
                $hostnames[] = new Hostname((string) $name, (string) $type);
            }
        }

        return $hostnames;
    }

    /**
     * @return Script[]
     */
    public static function parseScripts(SimpleXMLElement $xmlScripts): array
    {
        $scripts = [];
        foreach ($xmlScripts as $xmlScript) {
            $attrs = $xmlScript->attributes();
            if (null === $attrs) {
                continue;
            }
            $scripts[] = new Script(
                $attrs->id,
                $attrs->output,
                isset($xmlScript->elem) || isset($xmlScript->table) ? self::parseScriptElems($xmlScript) : []
            );
        }

        return $scripts;
    }

    public static function parseScriptElem(SimpleXMLElement $xmlElems): array
    {
        $elems = [];
        foreach ($xmlElems as $xmlElem) {
            if (empty($xmlElem->attributes())) {
                $elems[] = (string) $xmlElem[0];
            } else {
                $attrs = $xmlElem->attributes();
                if (null === $attrs) {
                    continue;
                }
                $elems[(string) $attrs->key] = (string) $xmlElem[0];
            }
        }
        return $elems;
    }

    public static function parseScriptElems(SimpleXMLElement $xmlScript): array
    {
        if (isset($xmlScript->table)) {
            $elems = [];
            foreach ($xmlScript->table as $xmlTable) {
                $elems[(string) $xmlTable->attributes()->key] = self::parseScriptElem($xmlTable->elem);
            }
            return $elems;
        }

        return self::parseScriptElem($xmlScript->elem);
    }

    /**
     * @return Port[]
     */
    public static function parsePorts(SimpleXMLElement $xmlPorts): array
    {
        $ports = [];
        foreach ($xmlPorts as $xmlPort) {
            $name = $product = $version = null;

            if ($xmlPort->service) {
                $attrs = $xmlPort->service->attributes();
                if (!is_null($attrs)) {
                    $name = (string) $attrs->name;
                    $product = (string) $attrs->product;
                    $version = $attrs->version;
                }
            }

            $service = new Service(
                $name,
                $product,
                $version
            );

            $attrs = $xmlPort->attributes();
            if (!is_null($attrs)) {
                $port = new Port(
                    (int) $attrs->portid,
                    (string) $attrs->protocol,
                    (string) $xmlPort->state->attributes()->state,
                    $service
                );
                if (isset($xmlPort->script)) {
                    $port->setScripts(self::parseScripts($xmlPort->script));
                }
                $ports[] = $port;
            }
        }

        return $ports;
    }

    /**
     * @return Address[]
     */
    public static function parseAddresses(SimpleXMLElement $host): array
    {
        $addresses = [];
        foreach ($host->xpath('./address') as $address) {
            $attributes = $address->attributes();
            if (is_null($attributes)) {
                continue;
            }
            $addresses[(string) $attributes->addr] = new Address(
                (string) $attributes->addr,
                (string) $attributes->addrtype,
                isset($attributes->vendor) ? (string) $attributes->vendor : ''
            );
        }

        return $addresses;
    }

}
