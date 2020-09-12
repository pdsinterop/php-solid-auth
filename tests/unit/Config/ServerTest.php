<?php

namespace Pdsinterop\Solid\Auth\Config;

use ArgumentCountError;
use Pdsinterop\Solid\Auth\Enum\OpenId\OpenIdConnectMetadata as OidcMeta;
use Pdsinterop\Solid\Auth\Exception\LogicException;
use PHPUnit\Framework\TestCase;

class ServerTest extends TestCase
{
    final public function testServerConfigShouldComplainWhenInstantiatedWithoutData() : void
    {
        $this->expectException(ArgumentCountError::class);
        $this->expectExceptionMessage('Too few arguments to function');

        /** @noinspection PhpParamsInspection */
        new Server();
    }

    final public function testServerConfigShouldInstantiatedWhenGivenData() : void
    {
        $actual = new Server([]);
        $expected = Server::class;

        self::assertInstanceOf($expected, $actual);
    }

    final public function testServerConfigShouldProvideRequiredPropertiesWhenAskedForRequiredProperties() : void
    {
        $server = new Server([]);
        $actual = $server->getRequired();

        $expected = [
            OidcMeta::AUTHORIZATION_ENDPOINT,
            OidcMeta::ID_TOKEN_SIGNING_ALG_VALUES_SUPPORTED,
            OidcMeta::ISSUER,
            OidcMeta::JWKS_URI,
            OidcMeta::RESPONSE_TYPES_SUPPORTED,
            OidcMeta::SUBJECT_TYPES_SUPPORTED,
        ];

        self::assertEquals($expected, $actual);
    }

    final public function testServerConfigShouldNotBeValidWhenMissingRequiredProperties() : void
    {
        $server = new Server([]);
        $actual = $server->validate();

        self::assertFalse($actual);
    }

    final public function testServerConfigShouldBeValidWhenGivenAllRequiredProperties() : void
    {
        $required = (new Server([]))->getRequired();
        $data = array_combine($required, $required);

        $server = new Server($data);
        $server->getRequired();
        $actual = $server->validate();

        self::assertTrue($actual);
    }

    final public function testServerConfigShouldComplainWhenSerializedWithRequiredKeysMissing() : void
    {
        $this->expectException(LogicException::class);
        $this->expectExceptionMessage('Required properties have not been set: authorization_endpoint, id_token_signing_alg_values_supported, issuer, jwks_uri, response_types_supported, subject_types_supported');

        $server = new Server([]);

        $server->jsonSerialize();
    }

    final public function testServerConfigShouldReturnArrayWhenSerializedWithRequiredKeysPresent() : array
    {
        $required = (new Server([]))->getRequired();
        $data = array_combine($required, $required);

        $server = new Server($data);

        $actual = $server->jsonSerialize();

        self::assertIsArray($actual);

        return $actual;
    }

    /**
     * @depends testServerConfigShouldReturnArrayWhenSerializedWithRequiredKeysPresent
     */
    final public function testServerConfigShouldReturnExpectedValuesWhenSerializedWithRequiredKeysPresent(array $actual)
    {
        self::assertEquals($actual,  [
            'authorization_endpoint' => 'authorization_endpoint',
            'id_token_signing_alg_values_supported' => 'id_token_signing_alg_values_supported',
            'issuer' => 'issuer',
            'jwks_uri' => 'jwks_uri',
            'response_types_supported' => 'response_types_supported',
            'subject_types_supported' => 'subject_types_supported',
        ]);
    }
}
