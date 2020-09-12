<?php

namespace Pdsinterop\Solid\Auth\Enum;

use PHPUnit\Framework\TestCase;

abstract class AbstractEnumTest extends TestCase
{
    public const TEST_VALUE = 'test';

    /** @var AbstractEnum */
    private $enum;

    /** @return AbstractEnum */
    abstract public function getEnum();

    /** @return string[] */
    abstract public function getExpectedValues() : array;

    abstract public function getTestValue() : string;

    final public function setUp() : void
    {
        $this->enum = $this->getEnum();
    }

    final public function testEnumShouldBeCreatedWhenInstantiated() : void
    {
        $actual = $this->enum;

        self::assertInstanceOf(AbstractEnum::class, $actual);
    }

    final public function testEnumShouldReturnTrueWhenStaticallyAskedForDeclaredEnum() : void
    {
        $enum = $this->enum;

        $actual = $enum::has($this->getTestValue());

        self::assertTrue($actual);
    }

    final public function testEnumShouldReturnFalseWhenStaticallyAskedForUndeclaredEnum() : void
    {
        $enum = $this->enum;

        $actual = $enum::has('non-existing');

        self::assertFalse($actual);
    }

    final public function testEnumShouldReturnTrueWhenAskedForDeclaredEnum() : void
    {
        $enum = $this->enum;
        $actual = $enum->hasValue(static::TEST_VALUE);

        self::assertTrue($actual);
    }

    final public function testEnumShouldReturnFalseWhenAskedForUndeclaredEnum() : void
    {
        $enum = $this->enum;

        $actual = $enum->hasValue('non-existing');

        self::assertFalse($actual);
    }

    final public function testEnumShouldReturnArrayWhenAskedForValues() : array
    {
        $enum = $this->enum;

        $actual = $enum->getValues();

        self::assertIsArray($actual);

        return $actual;
    }

    /**
     * @param array $actual
     *
     * @depends testEnumShouldReturnArrayWhenAskedForValues
     */
    final public function testEnumValuesShouldMatchExpectedValues(array $actual) : void
    {
        $expected = $this->getExpectedValues();

        self::assertEquals($actual, $expected);
    }
}
