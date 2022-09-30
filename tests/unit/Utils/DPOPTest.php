<?php

namespace Pdsinterop\Solid\Auth\Utils;

use Laminas\Diactoros\ServerRequest;
use Lcobucci\JWT\Validation\RequiredConstraintsViolated;
use Pdsinterop\Solid\Auth\AbstractTestCase;
use Pdsinterop\Solid\Auth\Enum\Jwk\Parameter as JwkParameter;
use Pdsinterop\Solid\Auth\Exception\AuthorizationHeaderException;
use Pdsinterop\Solid\Auth\Exception\InvalidTokenException;

/**
 * @coversDefaultClass \Pdsinterop\Solid\Auth\Utils\DPop
 * @covers ::<!public>
 * @covers ::__construct
 *
 * @uses \Pdsinterop\Solid\Auth\Utils\Base64Url
 * @uses \Pdsinterop\Solid\Auth\Utils\JtiValidator
 */
class DPOPTest extends AbstractTestCase
{
    ////////////////////////////////// FIXTURES \\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\

    const MOCK_SUBJECT = 'mock sub';
    const MOCK_THUMBPRINT = 'Mock Thumbprint';

    private $dpop;
    private $url;
    private $serverRequest;
    private $accessToken;

    protected function setUp(): void
    {
        $keyPath    = __DIR__ . '/../../fixtures/keys';
        $privateKey = file_get_contents($keyPath . '/private.key');
        $publicKey  = file_get_contents($keyPath . '/public.key');

        //https://datatracker.ietf.org/doc/html/rfc9068#section-2.2
        $this->accessToken = $this->sign([
            "header" => [
                'typ' => 'jwt',
                'alg' => 'RS256'
            ],
            "payload" => [
                'iss' => 'example.com',
                'iat' => time(),
                'exp' => time()+3600,
                'aud' => 'example.com',
                'sub' => self::MOCK_SUBJECT,
                'jti' => time() // any changing value will do for the tests
            ]
        ]); 

        $keyInfo = \openssl_pkey_get_details(\openssl_pkey_get_public($publicKey));
        $jwk = [
            'kty' => 'RSA',
            'n' => Base64Url::encode($keyInfo['rsa']['n']),
            'e' => Base64Url::encode($keyInfo['rsa']['e']),
        ];

        $header = [
            'typ' => 'dpop+jwt',
            'alg' => 'RS256',
            'jwk' => $jwk,
        ];

        $payload = [
            'iss' => 'example.com',
            'aud' => 'example.com',
            'htm' => 'GET',
            'htu' => 'https://www.example.com',
            'iat' => time(),
            'nbf' => time(),
            'exp' => time()+3600,
            'ath' => hash('SHA256', $this->accessToken['token']),
            'jti' => time() // any changing value will do for the tests
        ];

        $this->dpop = $this->sign([
            'header' => $header,
            'payload' => $payload,
        ]);

        $this->url = 'https://www.example.com';
        $this->serverRequest = new ServerRequest(array(),array(), $this->url);
    }

    private function getWrongKey()
    {
        $keyPath  = __DIR__ . '/../../fixtures/keys';
        $wrongKey = file_get_contents($keyPath . '/wrong.key');

        $keyInfo = \openssl_pkey_get_details(\openssl_pkey_get_public($wrongKey));
        return $keyInfo;
    }

    /////////////////////////////////// TESTS \\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\

    /**
     * @testdox Dpop SHOULD complain WHEN instantiated without JtiValidator
     */
    final public function testInstantiationWithoutJtiValidator(): void
    {
        $this->expectArgumentCountError(1);

        new DPop();
    }

    /**
     * @testdox Dpop SHOULD be created WHEN instantiated with JtiValidator
     */
    final public function testInstantiation(): void
    {
        $mockJtiValidator = $this->createMockJtiValidator();
        $actual = new DPop($mockJtiValidator);
        $expected = DPop::class;

        $this->assertInstanceOf($expected, $actual);
    }

    /**
     * @testdox Dpop SHOULD complain WHEN asked to validate DPOP without JWT given
     *
     * @covers ::validateDpop
     */
    final public function testValidateDpopWithoutJwt(): void
    {
        $this->expectArgumentCountError(1);

        $mockJtiValidator = $this->createMockJtiValidator();
        $dpop = new DPop($mockJtiValidator);

        $dpop->validateDpop();
    }

    /**
     * @testdox Dpop SHOULD complain WHEN asked to validate DPOP without Request given
     *
     * @covers ::validateDpop
     */
    final public function testValidateDpopWithoutRequest(): void
    {
        $this->expectArgumentCountError(2);

        $mockJtiValidator = $this->createMockJtiValidator();
        $dpop = new DPop($mockJtiValidator);

        $dpop->validateDpop('mock jwt');
    }

    /**
     * @testdox Dpop SHOULD complain WHEN asked to validate a DPOP with wrong header type
     *
     * @covers ::validateDpop
     */
    public function testValidateDpopWithWrongTyp(): void
    {
        $this->dpop['header']['typ'] = 'jwt';
        $token = $this->sign($this->dpop);

        $mockJtiValidator = $this->createMockJtiValidator();
        $dpop = new DPop($mockJtiValidator);

        $this->expectException(InvalidTokenException::class);
        $this->expectExceptionMessage('typ is not dpop+jwt');

        $result = $dpop->validateDpop($token['token'], $this->serverRequest);
    }

    /**
     * @testdox Dpop SHOULD complain WHEN asked to validate a DPOP with encryption algorithm "none"
     *
     * @covers ::validateDpop
     */
    public function testValidateDpopWithAlgNone(): void
    {
        $this->dpop['header']['alg'] = 'none';
        $token = $this->sign($this->dpop);

        $mockJtiValidator = $this->createMockJtiValidator();
        $dpop = new DPop($mockJtiValidator);

        $this->expectException(InvalidTokenException::class);
        $this->expectExceptionMessage('alg is none');
        $result = $dpop->validateDpop($token['token'], $this->serverRequest);
        $this->assertTrue($result);
    }

    /**
     * @testdox Dpop SHOULD complain WHEN asked to validate a DPOP with mismatched public key
     *
     * @covers ::validateDpop
     */
    public function testValidateDpopWithWrongKey(): void
    {
        $theWrongKey = $this->getWrongKey();
        $this->dpop['header']['jwk'] = [
            'kty' => 'RSA',
            'n' => Base64Url::encode($theWrongKey['rsa']['n']),
            'e' => Base64Url::encode($theWrongKey['rsa']['e']),
        ];
        $token = $this->sign($this->dpop);

        $mockJtiValidator = $this->createMockJtiValidator();
        $dpop = new DPop($mockJtiValidator);

        try {
            $dpop->validateDpop($token['token'], $this->serverRequest);
        } catch(RequiredConstraintsViolated $e) {
            // need to check the actual violation in the exception, so expectExceptionMessage is not sufficient
            $this->assertSame($e->violations()[0]->getMessage(),'Token signature mismatch');
        }
    }

    /**
     * @testdox Dpop SHOULD return true WHEN asked to validate a valid DPOP
     *
     * @covers ::validateDpop
     */
    public function testValidateDpopWithCorrectToken(): void
    {
        $this->dpop['payload']['jti'] = 'mock jti';

        $token = $this->sign($this->dpop);

        $mockJtiValidator = $this->createMockJtiValidator();

        $mockJtiValidator->expects($this->once())
            ->method('validate')
            ->willReturn(true)
        ;

        $dpop = new DPop($mockJtiValidator);

        $result = $dpop->validateDpop($token['token'], $this->serverRequest);

        $this->assertTrue($result);
    }

    /**
     * @testdox Dpop SHOULD complain WHEN asked to get WebId without Request given
     *
     * @covers ::getWebId
     * @uses \Pdsinterop\Solid\Auth\Utils\DPop::validateJwtDpop
     */
    final public function testGetWebIdWithoutRequest(): void
    {
        $mockJtiValidator = $this->createMockJtiValidator();
        $dpop = new DPop($mockJtiValidator);

        $this->expectArgumentCountError(1);

        $dpop->getWebId();
    }

    /**
     * @testdox Dpop SHOULD return 'public' WHEN asked to get WebId from Request without Authorization Header
     *
     * @covers ::getWebId
     * @uses \Pdsinterop\Solid\Auth\Utils\DPop::validateJwtDpop
     */
    final public function testGetWebIdWithoutHttpAuthorizationHeader(): void
    {
        $mockJtiValidator = $this->createMockJtiValidator();
        $dpop = new DPop($mockJtiValidator);

        $request = new ServerRequest(array(),array(), $this->url);

        $actual = $dpop->getWebId($request);
        $expected = 'public';

        $this->assertEquals($expected, $actual);
    }

    /**
     * @testdox Dpop SHOULD complain WHEN asked to get WebId from Request with incorrect Authorization Header format
     *
     * @covers ::getWebId
     * @uses \Pdsinterop\Solid\Auth\Utils\DPop::validateJwtDpop
     */
    final public function testGetWebIdWithIncorrectAuthHeaderFormat(): void
    {
        $mockJtiValidator = $this->createMockJtiValidator();
        $dpop = new DPop($mockJtiValidator);

        $request = new ServerRequest(array('HTTP_AUTHORIZATION' => 'IncorrectAuthorizationFormat'),array(), $this->url);

        $this->expectException(AuthorizationHeaderException::class);
        $this->expectExceptionMessage('Authorization Header does not contain parameters');

        $dpop->getWebId($request);
    }

    /**
     * @testdox Dpop SHOULD complain WHEN asked to get WebId from Request with invalid JWT
     *
     * @covers ::getWebId
     * @uses \Pdsinterop\Solid\Auth\Utils\DPop::getDpopKey
     * @uses \Pdsinterop\Solid\Auth\Utils\DPop::validateDpop
     * @uses \Pdsinterop\Solid\Auth\Utils\DPop::validateJwtDpop
     */
    final public function testGetWebIdWithInvalidJwt(): void
    {
        $mockJtiValidator = $this->createMockJtiValidator();
        $dpop = new DPop($mockJtiValidator);

        $this->expectException(InvalidTokenException::class);
        $this->expectExceptionMessage('Invalid DPoP token');

        $request = new ServerRequest(array(
            'HTTP_AUTHORIZATION' => "dpop Invalid JWT",
            'HTTP_DPOP' => 'Invalid dpop',
        ),array(), $this->url);

        $dpop->getWebId($request);
    }

    /**
     * @testdox Dpop SHOULD complain WHEN asked to get WebId from Request without DPOP authorization
     *
     * @covers ::getWebId
     * @uses \Pdsinterop\Solid\Auth\Utils\DPop::validateJwtDpop
     */
    final public function testGetWebIdWithoutDpop(): void
    {
        $mockJtiValidator = $this->createMockJtiValidator();
        $dpop = new DPop($mockJtiValidator);

        $this->expectException(AuthorizationHeaderException::class);
        $this->expectExceptionMessage('Only "dpop" authorization scheme is supported');

        $request = new ServerRequest(array('HTTP_AUTHORIZATION' => "Basic YWxhZGRpbjpvcGVuc2VzYW1l"),array(), $this->url);

        $dpop->getWebId($request);
    }

    /**
     * @testdox Dpop SHOULD return given "sub" WHEN asked to get WebId from Request with valid DPOP without JWT Key Id
     *
     * @covers ::getWebId
     *
     * @uses \Pdsinterop\Solid\Auth\Utils\DPop::getDpopKey
     * @uses \Pdsinterop\Solid\Auth\Utils\DPop::validateDpop
     * @uses \Pdsinterop\Solid\Auth\Utils\DPop::validateJwtDpop
     */
    final public function testGetWebIdWithDpopWithoutKeyId(): void
    {
        $this->dpop['payload']['cnf'] = ['jkt' => self::MOCK_THUMBPRINT];
        $this->dpop['payload']['jti'] = 'mock jti';
        $this->dpop['payload']['sub'] = self::MOCK_SUBJECT;

        $dpopToken = $this->sign($this->dpop);

        $mockJtiValidator = $this->createMockJtiValidator();

        $mockJtiValidator->expects($this->once())
            ->method('validate')
            ->willReturn(true)
        ;

        $dpop = new DPop($mockJtiValidator);

        $request = new ServerRequest(array(
            'HTTP_AUTHORIZATION' => "dpop {$this->accessToken['token']}",
            'HTTP_DPOP' => $dpopToken['token'],
        ),array(), $this->url);

        $actual = $dpop->getWebId($request);
        $expected = 'mock sub';

        $this->assertEquals($expected, $actual);
    }

    /**
     * @testdox Dpop SHOULD complain WHEN asked to get WebId from Request with valid DPOP without Confirmation Claim
     * @covers ::getWebId
     *
     * @uses \Pdsinterop\Solid\Auth\Utils\DPop::getDpopKey
     * @uses \Pdsinterop\Solid\Auth\Utils\DPop::validateDpop
     * @uses \Pdsinterop\Solid\Auth\Utils\DPop::validateJwtDpop
     */
    final public function testGetWebIdWithDpopWithoutConfirmationClaim(): void
    {
        $this->markTestSkipped('Skipped untill we find a spec that requires this');
        $this->dpop['header']['jwk'][JwkParameter::KEY_ID] = self::MOCK_THUMBPRINT;
        $this->dpop['payload']['jti'] = 'mock jti';
        $this->dpop['payload']['sub'] = self::MOCK_SUBJECT;

        $token = $this->sign($this->dpop);

        $mockJtiValidator = $this->createMockJtiValidator();

        $mockJtiValidator->expects($this->once())
            ->method('validate')
            ->willReturn(true)
        ;

        $dpop = new DPop($mockJtiValidator);

        $request = new ServerRequest(array(
            'HTTP_AUTHORIZATION' => "dpop {$token['token']}",
            'HTTP_DPOP' => $token['token'],
        ),array(), $this->url);

        $this->expectException(InvalidTokenException::class);
        $this->expectExceptionMessage('JWT Confirmation claim (cnf) is missing');

        $dpop->getWebId($request);
    }

    /**
     * @testdox Dpop SHOULD complain WHEN asked to get WebId from Request with valid DPOP without JWT Key Thumbprint
     * @covers ::getWebId
     *
     * @uses \Pdsinterop\Solid\Auth\Utils\DPop::getDpopKey
     * @uses \Pdsinterop\Solid\Auth\Utils\DPop::validateDpop
     * @uses \Pdsinterop\Solid\Auth\Utils\DPop::validateJwtDpop
     */
    final public function testGetWebIdWithDpopWithoutThumbprint(): void
    {
        $this->markTestSkipped('Skipped untill we find a spec that requires this');
        $this->dpop['header']['jwk'][JwkParameter::KEY_ID] = self::MOCK_THUMBPRINT;
        $this->dpop['payload']['cnf'] = [];
        $this->dpop['payload']['jti'] = 'mock jti';
        $this->dpop['payload']['sub'] = self::MOCK_SUBJECT;

        $token = $this->sign($this->dpop);

        $mockJtiValidator = $this->createMockJtiValidator();
        $mockJtiValidator->expects($this->once())
            ->method('validate')
            ->willReturn(true)
        ;
        $dpop = new DPop($mockJtiValidator);

        $request = new ServerRequest(array(
            'HTTP_AUTHORIZATION' => "dpop {$token['token']}",
            'HTTP_DPOP' => $token['token'],
        ),array(), $this->url);

        $this->expectException(InvalidTokenException::class);
        $this->expectExceptionMessage('JWT Confirmation claim (cnf) is missing Thumbprint (jkt)');

        $dpop->getWebId($request);
    }

    /**
     * @testdox Dpop SHOULD complain WHEN asked to get WebId from Request with valid DPOP with Thumbprint not matching Key Id
     * @covers ::getWebId
     *
     * @uses \Pdsinterop\Solid\Auth\Utils\DPop::getDpopKey
     * @uses \Pdsinterop\Solid\Auth\Utils\DPop::validateDpop
     * @uses \Pdsinterop\Solid\Auth\Utils\DPop::validateJwtDpop
     */
    final public function testGetWebIdWithDpopWithMismatchingThumbprintAndKeyId(): void
    {
        $this->markTestSkipped('Skipped untill we find a spec that requires this');
        $this->dpop['header']['jwk'][JwkParameter::KEY_ID] = self::MOCK_THUMBPRINT . 'Mismatch';
        $this->dpop['payload']['cnf'] = ['jkt' => self::MOCK_THUMBPRINT];
        $this->dpop['payload']['jti'] = 'mock jti';
        $this->dpop['payload']['sub'] = self::MOCK_SUBJECT;

        $token = $this->sign($this->dpop);

        $mockJtiValidator = $this->createMockJtiValidator();
        $mockJtiValidator->expects($this->once())
            ->method('validate')
            ->willReturn(true)
        ;
        $dpop = new DPop($mockJtiValidator);

        $request = new ServerRequest(array(
            'HTTP_AUTHORIZATION' => "dpop {$token['token']}",
            'HTTP_DPOP' => $token['token'],
        ),array(), $this->url);

        $this->expectException(InvalidTokenException::class);
        $this->expectExceptionMessage('JWT Confirmation claim (cnf) provided Thumbprint (jkt) does not match Key ID from JWK header');

        $dpop->getWebId($request);
    }

    /**
     * @testdox Dpop SHOULD complain WHEN asked to get WebId from Request with valid DPOP without "sub"
     *
     * @covers ::getWebId
     *
     * @uses \Pdsinterop\Solid\Auth\Utils\DPop::getDpopKey
     * @uses \Pdsinterop\Solid\Auth\Utils\DPop::validateDpop
     * @uses \Pdsinterop\Solid\Auth\Utils\DPop::validateJwtDpop
     */
    final public function testGetWebIdWithDpopWithoutSub(): void
    {
        $this->dpop['header']['jwk'][JwkParameter::KEY_ID] = self::MOCK_THUMBPRINT;
        $this->dpop['payload']['cnf'] = ['jkt' => self::MOCK_THUMBPRINT];
        $this->dpop['payload']['jti'] = 'mock jti';
        $token = $this->sign($this->dpop);

        unset($this->accessToken['payload']['sub']);
        $accessToken = $this->sign($this->accessToken);

        $mockJtiValidator = $this->createMockJtiValidator();
        $mockJtiValidator->expects($this->once())
            ->method('validate')
            ->willReturn(true)
        ;
        $dpop = new DPop($mockJtiValidator);

        $request = new ServerRequest(array(
            'HTTP_AUTHORIZATION' => "dpop {$accessToken['token']}",
            'HTTP_DPOP' => $token['token'],
        ),array(), $this->url);

        $this->expectException(InvalidTokenException::class);
        $this->expectExceptionMessage('Missing "SUB"');

        $dpop->getWebId($request);
    }

    /**
     * @testdox Dpop SHOULD not complain WHEN asked to get WebId from Request with valid DPOP without "ath"
     *
     * @covers ::getWebId
     *
     * @uses \Pdsinterop\Solid\Auth\Utils\DPop::getDpopKey
     * @uses \Pdsinterop\Solid\Auth\Utils\DPop::validateDpop
     * @uses \Pdsinterop\Solid\Auth\Utils\DPop::validateJwtDpop
     */
    final public function testGetWebIdWithDpopWithoutOptionalAth(): void
    {
        unset($this->dpop['payload']['ath']);
        $token = $this->sign($this->dpop);

        $mockJtiValidator = $this->createMockJtiValidator();
        $mockJtiValidator->expects($this->once())
            ->method('validate')
            ->willReturn(true)
        ;
        $dpop = new DPop($mockJtiValidator);

        $request = new ServerRequest(array(
            'HTTP_AUTHORIZATION' => "dpop {$this->accessToken['token']}",
            'HTTP_DPOP' => $token['token'],
        ),array(), $this->url);

        $webId = $dpop->getWebId($request);

        $this->assertEquals(self::MOCK_SUBJECT, $webId);
    }
    /**
     * @testdox Dpop SHOULD complain WHEN asked to get WebId from Request with valid DPOP without "ath"
     *
     * @covers ::getWebId
     *
     * @uses \Pdsinterop\Solid\Auth\Utils\DPop::getDpopKey
     * @uses \Pdsinterop\Solid\Auth\Utils\DPop::validateDpop
     * @uses \Pdsinterop\Solid\Auth\Utils\DPop::validateJwtDpop
     */
    final public function testGetWebIdWithDpopWithoutRequiredAth(): void
    {
        /*/ @see https://github.com/pdsinterop/php-solid-auth/issues/34 /*/
        $this->markTestSkipped('ATH claim is not yet supported/required by the Solid OIDC specification.');

        unset($this->dpop['payload']['ath']);
        $token = $this->sign($this->dpop);

        $mockJtiValidator = $this->createMockJtiValidator();
        $mockJtiValidator->expects($this->once())
            ->method('validate')
            ->willReturn(true)
        ;
        $dpop = new DPop($mockJtiValidator);

        $request = new ServerRequest(array(
            'HTTP_AUTHORIZATION' => "dpop {$this->accessToken['token']}",
            'HTTP_DPOP' => $token['token'],
        ),array(), $this->url);

        $this->expectException(InvalidTokenException::class);
        $this->expectExceptionMessage('DPoP "ath" claim is missing');

        $dpop->getWebId($request);
    }

    /**
     * @testdox Dpop SHOULD return given "sub" WHEN asked to get WebId from Request with complete DPOP
     *
     * @covers ::getWebId
     *
     * @uses \Pdsinterop\Solid\Auth\Utils\DPop::getDpopKey
     * @uses \Pdsinterop\Solid\Auth\Utils\DPop::validateDpop
     * @uses \Pdsinterop\Solid\Auth\Utils\DPop::validateJwtDpop
     */
    final public function testGetWebIdWithDpop(): void
    {
        $this->dpop['header']['jwk'][JwkParameter::KEY_ID] = self::MOCK_THUMBPRINT;
        $this->dpop['payload']['cnf'] = ['jkt' => self::MOCK_THUMBPRINT];
        $this->dpop['payload']['jti'] = 'mock jti';
        $this->dpop['payload']['sub'] = self::MOCK_SUBJECT;

        $token = $this->sign($this->dpop);

        $mockJtiValidator = $this->createMockJtiValidator();

        $mockJtiValidator->expects($this->once())
            ->method('validate')
            ->willReturn(true)
        ;

        $dpop = new DPop($mockJtiValidator);

        $request = new ServerRequest(array(
            'HTTP_AUTHORIZATION' => "dpop {$this->accessToken['token']}",
            'HTTP_DPOP' => $token['token'],
        ),array(), $this->url);

        $actual = $dpop->getWebId($request);

        $this->assertEquals(self::MOCK_SUBJECT, $actual);
    }

    ////////////////////////////// MOCKS AND STUBS \\\\\\\\\\\\\\\\\\\\\\\\\\\\\

    private function createMockJtiValidator()
    {
        $mockJtiValidator = $this->getMockBuilder(JtiValidator::class)
            ->disableOriginalConstructor()
            ->getMock();

        return $mockJtiValidator;
    }

    ///////////////////////////// HELPER FUNCTIONS \\\\\\\\\\\\\\\\\\\\\\\\\\\\\

    protected function sign($dpop, $privateKey = null)
    {
        $keyPath = __DIR__ . '/../../fixtures/keys';
        if (!$privateKey) {
            $privateKey = file_get_contents($keyPath . '/private.key');
        }

        $signature = '';
        $success = \openssl_sign(
            Base64Url::encode(json_encode($dpop['header'])).'.'.
            Base64Url::encode(json_encode($dpop['payload'])),
            $signature,
            $privateKey,
            OPENSSL_ALGO_SHA256
        );

        if (!$success) {
            throw new \Exception('unable to sign dpop');
        }
        $token = Base64Url::encode(json_encode($dpop['header'])).'.'.
            Base64Url::encode(json_encode($dpop['payload'])).'.'.
            Base64Url::encode($signature);

        return array_merge($dpop, [
            'signature' => $signature,
            'token' => $token,
        ]);
    }
}
