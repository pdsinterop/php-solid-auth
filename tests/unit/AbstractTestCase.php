<?php declare(strict_types=1);

namespace Pdsinterop\Solid\Auth;

use ArgumentCountError;
use Pdsinterop\Solid\Auth\Utils\Base64Url;
use PHPUnit\Framework\TestCase;

abstract class AbstractTestCase extends TestCase
{
    ////////////////////////////// CUSTOM ASSERTS \\\\\\\\\\\\\\\\\\\\\\\\\\\\\\

    public function assertJwtEquals(array $expected, string $actual): void
    {
        $encoded = explode('.', $actual);

        $decoded = array_map(function ($encoded) {
            $decoded = Base64Url::decode($encoded);

            try {
                $decoded = json_decode($decoded, true, 512, JSON_THROW_ON_ERROR);
            } catch (\JsonException $e) {
                // Not (valid) JSON, return Base64Url decoded value
            }

            return $decoded;
        }, $encoded);


        // We can not easily compare the signatures in PHP, as the numeric
        // representation of the binary string is INF (infinity). So unless
        // something is passed to compare, we discard the signature
        if (count($decoded) === 3 && count($expected) === 2) {
            unset ($decoded[2]);
        }

        $this->assertEquals($expected, $decoded);
    }

    public function expectArgumentCountError(int $argumentCount): void
    {
        $this->expectException(ArgumentCountError::class);

        $this->expectExceptionMessageMatches('/Too few arguments [^,]+, ' . ($argumentCount - 1) . ' passed/');
    }
}
