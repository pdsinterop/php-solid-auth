<?php

namespace Pdsinterop\Solid\Auth\Config;

use ArgumentCountError;
use Pdsinterop\Solid\Auth\Enum\OpenId\OpenIdConnectMetadata as OidcMeta;
use Pdsinterop\Solid\Auth\Exception\LogicException;
use PHPUnit\Framework\TestCase;

/**
 * @coversNothing
 */
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
        $this->expectExceptionMessage('Required properties have not been set: authorization_endpoint, issuer, jwks_uri');

        $server = new Server([]);

        $server->jsonSerialize();
    }

    final public function testServerConfigShouldReturnArrayWhenSerializedWithRequiredKeysPresent() : array
    {
        $data = [
            OidcMeta::AUTHORIZATION_ENDPOINT => 'https://server/authorize',
            OidcMeta::ISSUER => 'https://server/identifier',
            OidcMeta::JWKS_URI => 'https://server/jwk'
        ];

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
        self::assertEquals([
            'authorization_endpoint' => 'https://server/authorize',
            'id_token_signing_alg_values_supported' => ['RS256'],
            'issuer' => 'https://server/identifier',
            'jwks_uri' => 'https://server/jwk',
            'response_types_supported' => ['code', 'id_token', 'token'],
            'subject_types_supported' => ['public'],
        ], $actual);
    }
}
