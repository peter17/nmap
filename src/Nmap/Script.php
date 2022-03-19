<?php

namespace Nmap;

class Script
{
    private string $id;

    private string $output;

    private array $elems;

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
