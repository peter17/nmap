<?php

namespace Nmap;

class XmlOutputParser
{

    /**
     * @param $xmlFile
     * @return Host[]
     */
    public static function parseOutputFile($xmlFile)
    {
        $xml = simplexml_load_file($xmlFile);

        $hosts = array();
        foreach ($xml->host as $xmlHost) {
            $host = new Host(
                self::parseAddresses($xmlHost),
                (string)$xmlHost->status->attributes()->state,
                isset($xmlHost->hostnames) ? self::parseHostnames($xmlHost->hostnames->hostname) : array(),
                isset($xmlHost->ports) ? self::parsePorts($xmlHost->ports->port) : array(),
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
     * @param \SimpleXMLElement $xmlHostnames
     * @return Hostname[]
     */
    public static function parseHostnames(\SimpleXMLElement $xmlHostnames)
    {
        $hostnames = array();
        foreach ($xmlHostnames as $hostname) {
            $attrs = $hostname->attributes();
            $name = $type = null;
            if (!is_null($attrs)) {
                $name = $attrs->name;
                $type = $attrs->type;
            }

            if (!is_null($name) && !is_null($type)) {
                $hostnames[] = new Hostname((string)$name, (string)$type);
            }
        }

        return $hostnames;
    }

    /**
     * @param \SimpleXMLElement $xmlHostscript
     * @return Script[]
     */
    public static function parseScripts(\SimpleXMLElement $xmlScripts)
    {
        $scripts = array();
        foreach ($xmlScripts as $xmlScript) {
            $attrs = $xmlScript->attributes();
            $scripts[] = new Script(
                $attrs->id,
                $attrs->output,
                isset($xmlScript->elem) || isset($xmlScript->table) ? self::parseScriptElems($xmlScript) : array()
            );
        }

        return $scripts;
    }

    public static function parseScriptElem(\SimpleXMLElement $xmlElems): array
    {
        $elems = array();
        foreach ($xmlElems as $xmlElem) {
            if (empty($xmlElem->attributes())) {
                $elems[] = (string) $xmlElem[0];
            } else {
                $elems[(string) $xmlElem->attributes()->key] = (string) $xmlElem[0];
            }
        }
        return $elems;
    }

    public static function parseScriptElems(\SimpleXMLElement $xmlScript): array
    {
        if (isset($xmlScript->table)) {
            $elems = array();
            foreach ($xmlScript->table as $xmlTable) {
                $elems[(string) $xmlTable->attributes()->key] = self::parseScriptElem($xmlTable->elem);
            }
            return $elems;
        }

        return self::parseScriptElem($xmlScript->elem);
    }

    /**
     * @param \SimpleXMLElement $xmlPorts
     * @return Port[]
     */
    public static function parsePorts(\SimpleXMLElement $xmlPorts): array
    {
        /**
         *
         */
        $ports = array();
        foreach ($xmlPorts as $xmlPort) {
            $name = $product = $version = null;

            if ($xmlPort->service) {
                $attrs = $xmlPort->service->attributes();
                if (!is_null($attrs)) {
                    $name = (string)$attrs->name;
                    $product = (string)$attrs->product;
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
                    (int)$attrs->portid,
                    (string)$attrs->protocol,
                    (string)$xmlPort->state->attributes()->state,
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
     * @param \SimpleXMLElement $host
     * @return Address[]
     */
    public static function parseAddresses(\SimpleXMLElement $host): array
    {
        $addresses = array();
        foreach ($host->xpath('./address') as $address) {
            $attributes = $address->attributes();
            if (is_null($attributes)) {
                continue;
            }
            $addresses[(string)$attributes->addr] = new Address(
                (string)$attributes->addr,
                (string)$attributes->addrtype,
                isset($attributes->vendor) ? (string)$attributes->vendor : ''
            );
        }

        return $addresses;
    }
}
