<?php

/**
 * This file is part of the nmap package.
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 *
 * @license    MIT License
 */

namespace Nmap\Util;

use InvalidArgumentException;
use RuntimeException;
use Symfony\Component\Process\ExecutableFinder;
use Symfony\Component\Process\Process;

class ProcessExecutor
{

    public function execute(array $command, int $timeout = 60): int
    {
        $executable = (new ExecutableFinder())->find($command[0]);
        if (!is_string($executable) || empty($executable)) {
            throw new InvalidArgumentException(sprintf('Unable to find executable `%s`', $command[0]));
        }
        $command[0] = $executable;

        $process = new Process($command, null, null, null, $timeout);
        $process->run();

        if (!$process->isSuccessful()) {
            throw new RuntimeException(sprintf(
                'Failed to execute "%s"'.PHP_EOL.'%s',
                implode(' ', $command),
                $process->getErrorOutput()
            ));
        }

        return (int) $process->getExitCode();
    }
}
