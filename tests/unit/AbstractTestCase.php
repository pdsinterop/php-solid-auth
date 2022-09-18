<?php declare(strict_types=1);

namespace Pdsinterop\Solid\Auth;

use ArgumentCountError;
use PHPUnit\Framework\TestCase;

abstract class AbstractTestCase extends TestCase
{
    ////////////////////////////// CUSTOM ASSERTS \\\\\\\\\\\\\\\\\\\\\\\\\\\\\\

    public function expectArgumentCountError(int $argumentCount): void
    {
        $this->expectException(ArgumentCountError::class);

        $this->expectExceptionMessageMatches('/Too few arguments [^,]+, ' . ($argumentCount - 1) . ' passed/');
    }
}
