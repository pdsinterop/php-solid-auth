<?php

namespace Pdsinterop\Solid\Auth\Utils;

use JsonSerializable;
use Lcobucci\JWT\Signer\Key;
use Pdsinterop\Solid\Auth\Enum\Jwk\Parameter as JwkParameter;
use Pdsinterop\Solid\Auth\Enum\Rsa\Parameter as RsaParameter;

class Jwks implements JsonSerializable
{
    ////////////////////////////// CLASS PROPERTIES \\\\\\\\\\\\\\\\\\\\\\\\\\\\

    /** @var Key */
    private $publicKey;

    //////////////////////////////// PUBLIC API \\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\

    final public function __construct(Key $publicKey)
    {
        $this->publicKey = $publicKey;
    }

    final public function __toString() : string
    {
        return (string) json_encode($this);
    }

    final public function jsonSerialize()
    {
        return $this->create();
    }

    ////////////////////////////// UTILITY METHODS \\\\\\\\\\\\\\\\\\\\\\\\\\\\\

    /**
     * @param string $certificate
     * @param $subject
     *
     * @return array
     */
    private function createKey(string $certificate, $subject) : array
    {
        return [
            JwkParameter::ALGORITHM => 'RS256',
            JwkParameter::KEY_ID => md5($certificate),
            JwkParameter::KEY_TYPE => 'RSA',
            RsaParameter::PUBLIC_EXPONENT => 'AQAB', // Hard-coded as `Base64Url::encode($keyInfo['rsa']['e'])` tends to be empty...
            RsaParameter::PUBLIC_MODULUS => Base64Url::encode($subject),
        ];
    }

    /**
     * As the JWT library does not (yet?) have support for JWK, a custom solution is used for now.
     *
     * @return array
     *
     * @see https://github.com/lcobucci/jwt/issues/32
     */
    private function create() : array
    {
        $jwks = ['keys' => []];

        $publicKeys = [$this->publicKey];

        array_walk($publicKeys, function (Key $publicKey) use (&$jwks) {
            $certificate = $publicKey->getContent();

            $key = openssl_pkey_get_public($certificate);
            $keyInfo = openssl_pkey_get_details($key);

            $jwks['keys'][] = $this->createKey($certificate, $keyInfo['rsa']['n']);
        });

        return $jwks;
    }
}