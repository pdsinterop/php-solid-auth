<?php

namespace Pdsinterop\Solid\Auth\Utils;

use PHPUnit\Framework\TestCase;
use Lcobucci\JWT\Validation\RequiredConstraintsViolated;

/**
 * @coversDefaultClass \Pdsinterop\Solid\Auth\Utils\DPop
 * @covers ::<!public>
 * @uses \Pdsinterop\Solid\Auth\Utils\Base64Url
 */
class DPOPTest extends TestCase
{
    ////////////////////////////////// FIXTURES \\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\

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
        $this->serverRequest = new \Laminas\Diactoros\ServerRequest(array(),array(), $this->url);
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
