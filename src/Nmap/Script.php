<?php

namespace Nmap;

class Script
{
    private string $id;

    private string $output;

    public function __construct($id, $output)
    {
        $this->id = $id;
        $this->output = $output;
    }

    public function getId()
    {
        return $this->id;
    }

    public function getOutput()
    {
        return $this->output;
    }
}
