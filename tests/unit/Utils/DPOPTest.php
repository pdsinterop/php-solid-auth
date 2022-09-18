<?php

namespace Pdsinterop\Solid\Auth\Utils;

use Laminas\Diactoros\ServerRequest;
use Lcobucci\JWT\Validation\RequiredConstraintsViolated;
use Pdsinterop\Solid\Auth\AbstractTestCase;
use Pdsinterop\Solid\Auth\Enum\Jwk\Parameter as JwkParameter;

/**
 * @coversDefaultClass \Pdsinterop\Solid\Auth\Utils\DPop
 * @covers ::<!public>
 *
 * @uses \Pdsinterop\Solid\Auth\Utils\Base64Url
 */
class DPOPTest extends AbstractTestCase
{
    ////////////////////////////////// FIXTURES \\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\

    const MOCK_SUBJECT = 'mock sub';
    const MOCK_THUMBPRINT = 'Mock Thumbprint';

    private $dpop;
    private $url;
    private $serverRequest;

    protected function setUp(): void
    {
        $keyPath    = __DIR__ . '/../../fixtures/keys';
        $privateKey = file_get_contents($keyPath . '/private.key');
        $publicKey  = file_get_contents($keyPath . '/public.key');

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
     * @testdox Dpop SHOULD be created WHEN instantiated without parameters
     */
    final public function testInstantiation(): void
    {
        $actual = new DPop();
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

        $dpop = new DPop();

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

        $dpop = new DPop();

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

        $dpop = new DPop();
        $this->expectException(\Exception::class);
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

        $dpop = new DPop();
        $this->expectException(\Exception::class);
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

        $dpop = new DPop();
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
        $token = $this->sign($this->dpop);

        $dpop = new DPop();
        $result = $dpop->validateDpop($token['token'], $this->serverRequest);
        $this->assertTrue($result);
    }

    /**
     * @testdox Dpop SHOULD complain WHEN asked to get WebId without Request given
     *
     * @covers ::getWebId
     */
    final public function testGetWebIdWithoutRequest(): void
    {
        $dpop = new DPop();

        $this->expectArgumentCountError(1);

        $dpop->getWebId();
    }

    /**
     * @testdox Dpop SHOULD complain WHEN asked to get WebId from Request without Authorization Header
     *
     * @covers ::getWebId
     */
    final public function testGetWebIdWithoutHttpAuthorizationHeader(): void
    {

        $dpop = new DPop();

        $request = new ServerRequest(array(),array(), $this->url);

        $this->markTestIncomplete('The current result is not testable (Undefined array key "HTTP_AUTHORIZATION")');

        $dpop->getWebId($request);
    }

    /**
     * @testdox Dpop SHOULD  return "public" WHEN asked to get WebId from Request with incorrect Authorization Header format
     *
     * @covers ::getWebId
     */
    final public function testGetWebIdWithIncorrectAuthHeaderFormat(): void
    {
        $dpop = new DPop();

        $request = new ServerRequest(array('HTTP_AUTHORIZATION' => 'IncorrectAuthorizationFormat'),array(), $this->url);

        $actual = $dpop->getWebId($request);
        $expected = 'public';

        $this->assertEquals($expected, $actual);
    }

    /**
     * @testdox Dpop SHOULD complain WHEN asked to get WebId from Request with invalid JWT
     *
     * @covers ::getWebId
     */
    final public function testGetWebIdWithInvalidJwt(): void
    {
        $dpop = new DPop();

        $this->expectException(\Exception::class);
        $this->expectExceptionMessage('Invalid JWT token');

        $request = new ServerRequest(array('HTTP_AUTHORIZATION' => 'Invalid JWT'),array(), $this->url);

        $dpop->getWebId($request);
    }

    /**
     * @testdox Dpop SHOULD return "public" WHEN asked to get WebId from Request with "Basic" authorization
     *
     * @covers ::getWebId
     */
    final public function testGetWebIdWithoutDpop(): void
    {
        $dpop = new DPop();

        $request = new ServerRequest(array('HTTP_AUTHORIZATION' => "Basic YWxhZGRpbjpvcGVuc2VzYW1l"),array(), $this->url);

        $this->expectException(\Exception::class);
        $this->expectExceptionMessage('Missing DPoP token');

        $this->markTestIncomplete('The current result is not testable (Undefined array key "HTTP_DPOP")');

        $actual = $dpop->getWebId($request);
    }

    /**
     * @testdox Dpop SHOULD complain WHEN asked to get WebId from Request with valid DPOP without JWT Key Id
     *
     * @covers ::getWebId
     *
     * @uses \Pdsinterop\Solid\Auth\Utils\DPop::getDpopKey
     * @uses \Pdsinterop\Solid\Auth\Utils\DPop::validateDpop
     */
    final public function testGetWebIdWithDpopWithoutKeyId(): void
    {
        $this->dpop['payload']['cnf'] = ['jkt' => self::MOCK_THUMBPRINT];
        $this->dpop['payload']['sub'] = self::MOCK_SUBJECT;

        $token = $this->sign($this->dpop);

        $dpop = new DPop();

        $request = new ServerRequest(array(
            'HTTP_AUTHORIZATION' => "dpop {$token['token']}",
            'HTTP_DPOP' => $token['token'],
        ),array(), $this->url);

        $this->expectException(\Exception::class);
        $this->expectExceptionMessage('Invalid token');

        $dpop->getWebId($request);
    }

    /**
     * @testdox Dpop SHOULD complain WHEN asked to get WebId from Request with valid DPOP without Confirmation Claim
     *
     * @covers ::getWebId
     *
     * @uses \Pdsinterop\Solid\Auth\Utils\DPop::getDpopKey
     * @uses \Pdsinterop\Solid\Auth\Utils\DPop::validateDpop
     */
    final public function testGetWebIdWithDpopWithoutConfirmationClaim(): void
    {
        $this->dpop['header']['jwk'][JwkParameter::KEY_ID] = self::MOCK_THUMBPRINT;
        $this->dpop['payload']['sub'] = self::MOCK_SUBJECT;

        $token = $this->sign($this->dpop);

        $dpop = new DPop();

        $request = new ServerRequest(array(
            'HTTP_AUTHORIZATION' => "dpop {$token['token']}",
            'HTTP_DPOP' => $token['token'],
        ),array(), $this->url);

        $this->expectException(\Exception::class);
        $this->expectExceptionMessage('Invalid token');

        $dpop->getWebId($request);
    }

    /**
     * @testdox Dpop SHOULD complain WHEN asked to get WebId from Request with valid DPOP without JWT Key Thumbprint
     *
     * @covers ::getWebId
     *
     * @uses \Pdsinterop\Solid\Auth\Utils\DPop::getDpopKey
     * @uses \Pdsinterop\Solid\Auth\Utils\DPop::validateDpop
     */
    final public function testGetWebIdWithDpopWithoutThumbprint(): void
    {
        $this->dpop['header']['jwk'][JwkParameter::KEY_ID] = self::MOCK_THUMBPRINT;
        $this->dpop['payload']['cnf'] = [];
        $this->dpop['payload']['sub'] = self::MOCK_SUBJECT;

        $token = $this->sign($this->dpop);

        $dpop = new DPop();

        $request = new ServerRequest(array(
            'HTTP_AUTHORIZATION' => "dpop {$token['token']}",
            'HTTP_DPOP' => $token['token'],
        ),array(), $this->url);

        $this->expectException(\Exception::class);
        $this->expectExceptionMessage('Invalid token');

        $dpop->getWebId($request);
    }

    /**
     * @testdox Dpop SHOULD complain WHEN asked to get WebId from Request with valid DPOP with Thumbprint not matching Key Id
     *
     * @covers ::getWebId
     *
     * @uses \Pdsinterop\Solid\Auth\Utils\DPop::getDpopKey
     * @uses \Pdsinterop\Solid\Auth\Utils\DPop::validateDpop
     */
    final public function testGetWebIdWithDpopWithMismatchingThumbprintAndKeyId(): void
    {
        $this->dpop['header']['jwk'][JwkParameter::KEY_ID] = self::MOCK_THUMBPRINT . 'Mismatch';
        $this->dpop['payload']['cnf'] = ['jkt' => self::MOCK_THUMBPRINT];
        $this->dpop['payload']['sub'] = self::MOCK_SUBJECT;

        $token = $this->sign($this->dpop);

        $dpop = new DPop();

        $request = new ServerRequest(array(
            'HTTP_AUTHORIZATION' => "dpop {$token['token']}",
            'HTTP_DPOP' => $token['token'],
        ),array(), $this->url);

        $this->expectException(\Exception::class);
        $this->expectExceptionMessage('Invalid token');

        $dpop->getWebId($request);
    }

    /**
     * @testdox Dpop SHOULD complain WHEN asked to get WebId from Request with valid DPOP without "sub"
     *
     * @covers ::getWebId
     *
     * @uses \Pdsinterop\Solid\Auth\Utils\DPop::getDpopKey
     * @uses \Pdsinterop\Solid\Auth\Utils\DPop::validateDpop
     */
    final public function testGetWebIdWithDpopWithoutSub(): void
    {
        $this->dpop['header']['jwk'][JwkParameter::KEY_ID] = self::MOCK_THUMBPRINT;
        $this->dpop['payload']['cnf'] = ['jkt' => self::MOCK_THUMBPRINT];

        $token = $this->sign($this->dpop);

        $dpop = new DPop();

        $request = new ServerRequest(array(
            'HTTP_AUTHORIZATION' => "dpop {$token['token']}",
            'HTTP_DPOP' => $token['token'],
        ),array(), $this->url);

        $this->expectException(\Exception::class);
        $this->expectExceptionMessage('Invalid token');

        $dpop->getWebId($request);
    }

    /**
     * @testdox Dpop SHOULD return given "sub" WHEN asked to get WebId from Request with complete DPOP
     *
     * @covers ::getWebId
     *
     * @uses \Pdsinterop\Solid\Auth\Utils\DPop::getDpopKey
     * @uses \Pdsinterop\Solid\Auth\Utils\DPop::validateDpop
     */
    final public function testGetWebIdWithDpop(): void
    {
        $this->dpop['header']['jwk'][JwkParameter::KEY_ID] = self::MOCK_THUMBPRINT;
        $this->dpop['payload']['cnf'] = ['jkt' => self::MOCK_THUMBPRINT];
        $this->dpop['payload']['sub'] = self::MOCK_SUBJECT;

        $token = $this->sign($this->dpop);

        $dpop = new DPop();

        $request = new ServerRequest(array(
            'HTTP_AUTHORIZATION' => "dpop {$token['token']}",
            'HTTP_DPOP' => $token['token'],
        ),array(), $this->url);

        $actual = $dpop->getWebId($request);

        $this->assertEquals(self::MOCK_SUBJECT, $actual);
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
