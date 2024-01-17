<?php

namespace Pdsinterop\Solid\Auth;

use Pdsinterop\Solid\Auth\Config\KeysInterface;
use Pdsinterop\Solid\Auth\Config\ServerInterface;
use Pdsinterop\Solid\Auth\Enum\OpenId\OpenIdConnectMetadata as OidcMeta;
use Pdsinterop\Solid\Auth\Utils\Base64Url;
use Pdsinterop\Solid\Auth\Utils\DPop;
use PHPUnit\Framework\MockObject\MockObject;

function time() { return 1234;}

/**
 * @coversDefaultClass \Pdsinterop\Solid\Auth\TokenGenerator
 * @covers ::__construct
 * @covers ::<!public>
 *
 * @uses \Pdsinterop\Solid\Auth\Utils\Base64Url
 */
class TokenGeneratorTest extends AbstractTestCase
{
    ////////////////////////////////// FIXTURES \\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\

    const MOCK_DPOP = "mock.dpop.value";
    const MOCK_JKT = 'mock jkt';

    private MockObject|Config $mockConfig;
    private MockObject|KeysInterface $mockKeys;

    private function createTokenGenerator($interval = null, $jkt = null): TokenGenerator
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

        $mockDpopUtil = $this->getMockBuilder(DPop::class)
            ->disableOriginalConstructor()
            ->getMock()
        ;

        if ($jkt) {
            $mockDpopUtil->expects($this->once())
                ->method('makeJwkThumbprint')
                ->willReturn($jkt)
            ;
        }

        return new TokenGenerator($this->mockConfig, $interval??$mockInterval, $mockDpopUtil);
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
     * @testdox Token Generator SHOULD complain WHEN instantiated without validity period
     *
     * @coversNothing
     */
    final public function testInstantiateWithoutValidFor(): void
    {
        $this->expectArgumentCountError(2);

        $mockConfig = $this->getMockBuilder(Config::class)
            ->disableOriginalConstructor()
            ->getMock();

        new TokenGenerator($mockConfig);
    }

    /**
     * @testdox Token Generator SHOULD complain WHEN instantiated without Dpop Utility
     *
     * @coversNothing
     */
    final public function testInstantiateWithoutDpopUtility(): void
    {
        $this->expectArgumentCountError(3);

        $mockConfig = $this->getMockBuilder(Config::class)
            ->disableOriginalConstructor()
            ->getMock();

        $mockInterval = $this->getMockBuilder(\DateInterval::class)
            ->disableOriginalConstructor()
            ->getMock()
        ;

        new TokenGenerator($mockConfig, $mockInterval);
    }

    /**
     * @testdox Token Generator SHOULD be created WHEN instantiated with Config and validity period
     *
     * @covers ::__construct
     */
    final public function testInstantiation(): void
    {
        $actual = $this->createTokenGenerator();

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

        $this->assertJwtEquals([[
                "alg" => "RS256",
                "typ" => "JWT",
            ], [
                "iss" => "mock issuer",
                "aud" => "mock client ID",
                "sub" => "mock client ID",
            ]], $actual);
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
     * @testdox Token Generator SHOULD generate a token without Confirmation JWT Thumbprint (CNF JKT) WHEN asked to generate a IdToken without dpopKey
     *
     * @covers ::generateIdToken
     */
    final public function testIdTokenGenerationWithoutDpopKey(): void
    {
        $validFor = new \DateInterval('PT1S');

        $tokenGenerator = $this->createTokenGenerator($validFor);


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

        $publicKey = file_get_contents(__DIR__.'/../fixtures/keys/public.key');

        $mockPublicKey = $this->getMockBuilder(\Lcobucci\JWT\Signer\Key::class)
            ->getMock()
        ;

        $mockPublicKey->expects($this->once())
            ->method('contents')
            ->willReturn($publicKey)
        ;

        $this->mockKeys->expects($this->once())
            ->method('getPublicKey')
            ->willReturn($this->mockPublicKey)
        ;

        $privateKey = file_get_contents(__DIR__.'/../fixtures/keys/private.key');

        $now = new \DateTimeImmutable('1234-01-01 12:34:56.789');

        $token = $tokenGenerator->generateIdToken(
            'mock access token',
            'mock clientId',
            'mock subject',
            'mock nonce',
            $privateKey,
            null,
            $now,
        );

        $this->assertJwtEquals([
            [
                'typ' => 'JWT',
                'alg' => 'RS256',
                'kid' => '0c3932ca20f3a00ad2eb72035f6cc9cb'
            ],
            [
                'at_hash' => '1EZBnvsFWlK8ESkgHQsrIQ',
                'aud' => 'mock clientId',
                'azp' => 'mock clientId',
                'c_hash' => '1EZBnvsFWlK8ESkgHQsrIQ',
                'exp' => -23225829903.789,
                'iat' => -23225829904.789,
                'iss' => 'mock issuer',
                'jti' => '4dc20036dbd8313ed055',
                'nbf' => -23225829905.789,
                'nonce' => 'mock nonce',
                'sub' => 'mock subject',
            ],
        ], $token);
    }

    /**
     * @testdox Token Generator SHOULD return a IdToken with a Confirmation JWT Thumbprint (CNF JKT) WHEN asked to generate a IdToken with clientId and privateKey and DPOP
     *
     * @covers ::generateIdToken
     *
     * @uses \Pdsinterop\Solid\Auth\Utils\Jwks
     */
    final public function testIdTokenGeneration(): void
    {
        $validFor = new \DateInterval('PT1S');

        $tokenGenerator = $this->createTokenGenerator($validFor, self::MOCK_JKT);

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

        $encodedDpop = vsprintf("%s.%s.%s", [
            'header' => Base64Url::encode('{"jwk":"mock jwk"}'),
            'body' => Base64Url::encode('{}'),
            'signature' => Base64Url::encode('mock signature')
        ]);

        $actual = $tokenGenerator->generateIdToken(
            'mock access token',
            'mock clientId',
            'mock subject',
            'mock nonce',
            $privateKey,
            $encodedDpop,
            $now
        );

        $this->assertJwtEquals([[
            "alg"=>"RS256",
            "typ"=>"JWT",
        ],[
            'at_hash' => '1EZBnvsFWlK8ESkgHQsrIQ',
            'aud' => 'mock clientId',
            'azp' => 'mock clientId',
            'c_hash' => '1EZBnvsFWlK8ESkgHQsrIQ',
            'cnf' => ["jkt" => self::MOCK_JKT],
            'exp' => -23225829903.789,
            'iat' => -23225829904.789,
            'iss' => 'mock issuer',
            'jti' => '4dc20036dbd8313ed055',
            'nbf' => -23225829905.789,
            'nonce' => 'mock nonce',
            'sub' => 'mock subject',
        ]], $actual);
    }
}
