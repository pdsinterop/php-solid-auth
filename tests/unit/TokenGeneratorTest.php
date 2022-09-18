<?php

namespace Pdsinterop\Solid\Auth;

use Pdsinterop\Solid\Auth\Config\KeysInterface;
use Pdsinterop\Solid\Auth\Config\ServerInterface;
use Pdsinterop\Solid\Auth\Enum\OpenId\OpenIdConnectMetadata as OidcMeta;
use Pdsinterop\Solid\Auth\Utils\Base64Url;
use PHPUnit\Framework\MockObject\MockObject;
use PHPUnit\Framework\TestCase;

function time() { return 1234;}

/**
 * @coversDefaultClass \Pdsinterop\Solid\Auth\TokenGenerator
 * @covers ::__construct
 * @covers ::<!public>
 *
 * @uses \Pdsinterop\Solid\Auth\Utils\Base64Url
 */
class TokenGeneratorTest extends TestCase
{
    ////////////////////////////////// FIXTURES \\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\

    private MockObject|Config $mockConfig;
    private MockObject|KeysInterface $mockKeys;

    private function createTokenGenerator($interval = null): TokenGenerator
    {
        $this->mockConfig = $this->getMockBuilder(Config::class)
            ->disableOriginalConstructor()
            ->getMock()
        ;

        $mockInterval = $this->getMockBuilder(\DateInterval::class)
            ->disableOriginalConstructor()
            ->getMock()
        ;

        $this->mockKeys = $this->getMockBuilder(KeysInterface::class)
            ->disableOriginalConstructor()
            ->getMock()
        ;

        $this->mockConfig->expects($this->atLeast(1))
            ->method('getKeys')
            ->willReturn($this->mockKeys)
        ;

        $this->mockKeys->expects($this->once())
            ->method('getEncryptionKey')
            ->willReturn('mock encryption key')
        ;

        return new TokenGenerator($this->mockConfig, $interval??$mockInterval);
    }

    ////////////////////////////// CUSTOM ASSERTS \\\\\\\\\\\\\\\\\\\\\\\\\\\\\\

    private function expectArgumentCountError(int $argumentCount): void
    {
        $this->expectException(\ArgumentCountError::class);

        $this->expectExceptionMessageMatches('/Too few arguments [^,]+, ' . ($argumentCount - 1) . ' passed/');
    }

    /////////////////////////////////// TESTS \\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\

    /**
     * @testdox Token Generator SHOULD complain WHEN instantiated without Config
     *
     * @coversNothing
     */
    final public function testInstantiateWithoutConfig(): void
    {
        $this->expectArgumentCountError(1);

        new TokenGenerator();
    }

    /**
     * @testdox Token Generator SHOULD be created WHEN instantiated with Config and validity period
     *
     * @covers ::__construct
     */
    final public function testInstantiation(): void
    {
        $mockConfig = $this->getMockBuilder(Config::class)
            ->disableOriginalConstructor()
            ->getMock()
        ;

        $mockInterval = $this->getMockBuilder(\DateInterval::class)
            ->disableOriginalConstructor()
            ->getMock()
        ;

        $mockKeys = $this->getMockBuilder(KeysInterface::class)
            ->disableOriginalConstructor()
            ->getMock()
        ;

        $mockConfig->expects($this->once())
            ->method('getKeys')
            ->willReturn($mockKeys)
        ;

        $mockKeys->expects($this->once())
            ->method('getEncryptionKey')
            ->willReturn('mock key')
        ;

        $actual = new TokenGenerator($mockConfig, $mockInterval);
        $expected = TokenGenerator::class;

        $this->assertInstanceOf($expected, $actual);
    }

    /**
     * @testdox Token Generator SHOULD complain WHEN asked to generate a RegistrationAccessToken without clientId
     *
     * @covers ::generateRegistrationAccessToken
     */
    final public function testRegistrationAccessTokenGenerationWithoutClientId(): void
    {
        $tokenGenerator = $this->createTokenGenerator();

        $this->expectArgumentCountError(1);

        $tokenGenerator->generateRegistrationAccessToken();
    }

    /**
     * @testdox Token Generator SHOULD complain WHEN asked to generate a RegistrationAccessToken without privateKey
     *
     * @covers ::generateRegistrationAccessToken
     */
    final public function testRegistrationAccessTokenGenerationWithoutPrivateKey(): void
    {
        $tokenGenerator = $this->createTokenGenerator();

        $this->expectArgumentCountError(2);

        $tokenGenerator->generateRegistrationAccessToken('mock client ID');
    }

    /**
     * @testdox Token Generator SHOULD return a RegistrationAccessToken WHEN asked to generate a RegistrationAccessToken with clientId and privateKey
     *
     * @covers ::generateRegistrationAccessToken
     */
    final public function testRegistrationAccessTokenGeneration(): void
    {
        $tokenGenerator = $this->createTokenGenerator();

        $mockServer = $this->getMockBuilder(ServerInterface::class)
            ->disableOriginalConstructor()
            ->getMock()
        ;

        $this->mockConfig->expects($this->once())
            ->method('getServer')
            ->willReturn($mockServer)
        ;

        $mockServer->expects($this->once())
            ->method('get')
            ->with(OidcMeta::ISSUER)
            ->willReturn('mock issuer')
        ;

        $privateKey = file_get_contents(__DIR__.'/../fixtures/keys/private.key');

        $actual = $tokenGenerator->generateRegistrationAccessToken('mock client ID', $privateKey);

        $expected = <<<JWT
eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9.eyJpc3MiOiJtb2NrIGlzc3VlciIsImF1ZCI6Im1vY2sgY2xpZW50IElEIiwic3ViIjoibW9jayBjbGllbnQgSUQifQ.hNpQ3R3krigm6iQ-wWXDzy1bq_txFAlymXJZ4VZd9otTqSNZ8qWB1b2MW6RnFjwlTJrbPzD-yksAn0R7Wwhl5NYnvm-YNlQ6mqKybo-DIfFV6uw6b3b8R4BmfcxVhHuiGDYbBvKiO955KGA4t8FLlBBVLPdREz5w-LYRndDSdho3E62eKX5eKndufPRBOO8bzBJBSbrFLf6kj1hape9uyLvNEmeP9Rq26K98GmDRN-BxAoQlC_EodIgqajqETtKSzsf5bBasu6EpSOOOFGRijS8RCqBt4f1Kkb5ltE_t9TBp0ceBSOB6lGJEShieulEf5prBwLrYMkSFCVTpn5Gwow
JWT;
        $this->assertEquals($expected, $actual);
    }

    /**
     * @testdox Token Generator SHOULD complain WHEN asked to generate a IdToken without accessToken
     *
     * @covers ::generateIdToken
     */
    final public function testIdTokenGenerationWithoutAccesToken(): void
    {
        $tokenGenerator = $this->createTokenGenerator();

        $this->expectArgumentCountError(1);

        $tokenGenerator->generateIdToken();
    }

    /**
     * @testdox Token Generator SHOULD complain WHEN asked to generate a IdToken without clientId
     *
     * @covers ::generateIdToken
     */
    final public function testIdTokenGenerationWithoutClientId(): void
    {
        $tokenGenerator = $this->createTokenGenerator();

        $this->expectArgumentCountError(2);

        $tokenGenerator->generateIdToken('mock access token');
    }

    /**
     * @testdox Token Generator SHOULD complain WHEN asked to generate a IdToken without subject
     *
     * @covers ::generateIdToken
     */
    final public function testIdTokenGenerationWithoutSubject(): void
    {
        $tokenGenerator = $this->createTokenGenerator();

        $this->expectArgumentCountError(3);

        $tokenGenerator->generateIdToken('mock access token', 'mock clientId');
    }

    /**
     * @testdox Token Generator SHOULD complain WHEN asked to generate a IdToken without nonce
     *
     * @covers ::generateIdToken
     */
    final public function testIdTokenGenerationWithoutNonce(): void
    {
        $tokenGenerator = $this->createTokenGenerator();

        $this->expectArgumentCountError(4);

        $tokenGenerator->generateIdToken('mock access token', 'mock clientId', 'mock subject');
    }

    /**
     * @testdox Token Generator SHOULD complain WHEN asked to generate a IdToken without privateKey, $dpopKey
     *
     * @covers ::generateIdToken
     */
    final public function testIdTokenGenerationWithoutPrivateKey(): void
    {
        $tokenGenerator = $this->createTokenGenerator();

        $this->expectArgumentCountError(5);

        $tokenGenerator->generateIdToken(
            'mock access token',
            'mock clientId',
            'mock subject',
            'mock nonce'
        );
    }

    /**
     * @testdox Token Generator SHOULD complain WHEN asked to generate a IdToken without dpopKey
     *
     * @covers ::generateIdToken
     */
    final public function testIdTokenGenerationWithoutDpopKey(): void
    {
        $tokenGenerator = $this->createTokenGenerator();

        $this->expectArgumentCountError(6);

        $tokenGenerator->generateIdToken(
            'mock access token',
            'mock clientId',
            'mock subject',
            'mock nonce',
            'mock private key'
        );
    }

    /**
     * @testdox Token Generator SHOULD return a IdToken WHEN asked to generate a IdToken with clientId and privateKey
     *
     * @covers ::generateIdToken
     *
     * @uses \Pdsinterop\Solid\Auth\Utils\Jwks
     */
    final public function testIdTokenGeneration(): void
    {
        $validFor = new \DateInterval('PT1S');

        $tokenGenerator = $this->createTokenGenerator($validFor);

        $mockKey = \Lcobucci\JWT\Signer\Key\InMemory::file(__DIR__.'/../fixtures/keys/public.key');

        $this->mockKeys->expects($this->once())
            ->method('getPublicKey')
            ->willReturn($mockKey)
        ;

        $mockServer = $this->getMockBuilder(ServerInterface::class)
            ->disableOriginalConstructor()
            ->getMock()
        ;

        $this->mockConfig->expects($this->once())
            ->method('getServer')
            ->willReturn($mockServer)
        ;

        $mockServer->expects($this->once())
            ->method('get')
            ->with(OidcMeta::ISSUER)
            ->willReturn('mock issuer')
        ;

        $privateKey = file_get_contents(__DIR__.'/../fixtures/keys/private.key');

        $now = new \DateTimeImmutable('1234-01-01 12:34:56.789');

        $idToken = $tokenGenerator->generateIdToken(
            'mock access token',
            'mock clientId',
            'mock subject',
            'mock nonce',
            $privateKey,
            'mock dpop',
            $now
        );

        [$header, $body,] = explode('.', $idToken);

        $header = Base64Url::decode($header);
        $body = json_decode(Base64Url::decode($body), true);

        $this->assertEquals('{"typ":"JWT","alg":"RS256","kid":"0c3932ca20f3a00ad2eb72035f6cc9cb"}', $header);

        // @FIXME: Time-related values are unset, these do need to be tested.
        unset($body['exp'], $body['iat'], $body['nbf']);

        $this->assertEquals([
            'aud' => 'mock clientId',
            'azp' => 'mock clientId',
            'c_hash' => '1EZBnvsFWlK8ESkgHQsrIQ',
            'at_hash' => '1EZBnvsFWlK8ESkgHQsrIQ',
            'cnf' => ["jkt" => "mock dpop"],
            'iss' => 'mock issuer',
            'jti' => '4dc20036dbd8313ed055',
            'nonce' => 'mock nonce',
            'sub' => 'mock subject',
        ], $body);
    }
}
