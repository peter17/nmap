<?php

namespace Nmap;

class Script
{

    /**
     * @var string 
     */
    private $id;

    /**
     * @var string
     */
    private $output;

    /**
     * @var array
     */
    private $elems;

    public function __construct(string $id, string $output, array $elems)
    {
        $this->id = $id;
        $this->output = $output;
        $this->elems = $elems;
    }

    public function getId()
    {
        return $this->id;
    }

    public function getOutput()
    {
        return $this->output;
    }

    public function getElems()
    {
        return $this->elems;
    }
}
