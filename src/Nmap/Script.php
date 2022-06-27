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

    public function getId(): string
    {
        return $this->id;
    }

    public function getOutput(): string
    {
        return $this->output;
    }

    public function getElems(): array
    {
        return $this->elems;
    }
}
