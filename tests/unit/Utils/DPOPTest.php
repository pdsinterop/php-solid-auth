<?php

namespace Pdsinterop\Solid\Auth\Utils;

use PHPUnit\Framework\TestCase;
use Lcobucci\JWT\Validation\RequiredConstraintsViolated;

/**
 * @coversDefaultClass \Pdsinterop\Solid\Auth\Utils\DPop
 * @covers ::__construct
 * @covers ::<!public>
 * @uses \Pdsinterop\Solid\Auth\Utils\Base64Url
 */
class DPOPTest extends TestCase
{

	private $dpop;
	private $url;
	private $serverRequest;
    
	protected function sign($dpop, $privateKey=null)
	{
		$keyPath    = __DIR__ . '/../../fixtures/keys';
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
        	'token' => $token
        ]);
	}

	protected function setUp(): void
	{
		$keyPath    = dirname(__DIR__) . '/../fixtures/keys';
        $privateKey = file_get_contents($keyPath . '/private.key');
        $publicKey  = file_get_contents($keyPath . '/public.key');

        $keyInfo = \openssl_pkey_get_details(\openssl_pkey_get_public($publicKey));
        $jwk = [
            'kty' => 'RSA',
            'n' => Base64Url::encode($keyInfo['rsa']['n']),
            'e' => Base64Url::encode($keyInfo['rsa']['e'])
        ];

        $header = [
            'typ' => 'dpop+jwt',
            'alg' => 'RS256',
            'jwk' => $jwk
        ];

        $payload = [
            'iss' => 'example.com',
            'aud' => 'example.com',
            'htm' => 'GET',
            'htu' => 'https://www.example.com',
            'iat' => time(),
            'nbf' => time(),
            'exp' => time()+3600
        ];

        $this->dpop = $this->sign([
        	'header'  => $header,
        	'payload' => $payload
        ]);

		$this->url = 'https://www.example.com';
        $this->serverRequest = new \Laminas\Diactoros\ServerRequest(array(),array(), $this->url);

	}

	private function getWrongKey() {
        $key = <<<EOF
-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAiGzr51tpH6F2HwMUSKCX
zxyYfZyNJpKZWzNb3AMrNZTGlKDHHuVCkxNmHV0yFIxr3flRNmvxebLxsuYPAmCF
ccV1r+1Pry244MHOIq3aq5mIRq+smVSPk350WpyO4jn8mOLOiH+CYe9LXmJSPBvO
zZHwjEp+VmIGp5oDUZc5nnrf/UkQcj6jvKj0TanD8vGpDg9w3WbkQHWbFAMGPQdc
YF5CZ68QPKPS86/aOdcnyoliSyIMn9BhrSXS8+Q3fCZHsYgejUjD7e0sx/+gBCrW
MOuzbyD29mgbqETiSCZS1YLxgPnA34NRRKY06G0fMusXSGsXC+y7EU8JjTvTs4/L
PwIDAQAB
-----END PUBLIC KEY-----
EOF;
        // Get public key  
        $pubkey=\openssl_pkey_get_details(\openssl_pkey_get_public($key));  
        return $pubkey;
    }

    /**
     * @covers ::validateDpop
     */
	public function testWrongTyp(): void
    {
        $this->dpop['header']['typ'] = 'jwt';
        $token = $this->sign($this->dpop);

        $dpop = new DPop();
        $this->expectException(\Exception::class);
        $this->expectExceptionMessage('typ is not dpop+jwt');

        $result = $dpop->validateDpop($token['token'], $this->serverRequest);
    }

    /**
     * @covers ::validateDpop
     */
    public function testAlgNone(): void 
    {
        $this->dpop['header']['alg'] = 'none';
        $token = $this->sign($this->dpop);

        $dpop = new DPop();
        $this->expectException(\Exception::class);
        $this->expectExceptionMessage('alg is none');
        $result = $dpop->validateDpop($token['token'], $this->serverRequest);
    }

    /**
     * @covers ::validateDpop
     */
    public function testWrongKey(): void
    {
        $theWrongKey = $this->getWrongKey();
        $this->dpop['header']['jwk'] = [
            'kty' => 'RSA',
            'n' => Base64Url::encode($theWrongKey['rsa']['n']),
            'e' => Base64Url::encode($theWrongKey['rsa']['e'])
        ];
        $token = $this->sign($this->dpop);

        $dpop = new DPop();
        try {
        	$result = $dpop->validateDpop($token['token'], $this->serverRequest);
	    } catch(RequiredConstraintsViolated $e) {
	    	$result = false;
	    	$this->assertSame($e->violations()[0]->getMessage(),'Token signature mismatch');
    	}
    	$this->assertFalse($result);
    }

    /**
     * @covers ::validateDpop
     */
    public function testCorrectToken(): void
    {
        $token = $this->sign($this->dpop);

        $dpop = new DPop();
        $result = $dpop->validateDpop($token['token'], $this->serverRequest);
        $this->assertTrue($result);
    }

}