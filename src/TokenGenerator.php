<?php declare(strict_types=1);

namespace Pdsinterop\Solid\Auth;

use Pdsinterop\Solid\Auth\Exception\InvalidTokenException;
use Pdsinterop\Solid\Auth\Utils\DPop;
use Pdsinterop\Solid\Auth\Utils\Jwks;
use Pdsinterop\Solid\Auth\Utils\Base64Url;
use Pdsinterop\Solid\Auth\Enum\OpenId\OpenIdConnectMetadata as OidcMeta;
use Laminas\Diactoros\Response\JsonResponse;
use League\OAuth2\Server\CryptTrait;

use Lcobucci\JWT\Configuration;
use Lcobucci\JWT\Signer\Key\InMemory;
use Lcobucci\JWT\Signer\Rsa\Sha256;

class TokenGenerator
{
    ////////////////////////////// CLASS PROPERTIES \\\\\\\\\\\\\\\\\\\\\\\\\\\\

    use CryptTrait; // Used to decrypt the 'code' information;

    public Config $config;

    private \DateInterval $validFor;
    private DPop $dpopUtil;

    //////////////////////////////// PUBLIC API \\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\

    final public function __construct(
        Config $config,
        \DateInterval $validFor,
        DPop $dpopUtil,
    ) {
        $this->config = $config;
        $this->dpopUtil = $dpopUtil;
        $this->validFor = $validFor;

        // Set the decryption key for the CryptTrait, used to decrypt the 'code' information
        $this->setEncryptionKey($this->config->getKeys()->getEncryptionKey());
    }

    public function generateRegistrationAccessToken($clientId, $privateKey) {
        $issuer = $this->config->getServer()->get(OidcMeta::ISSUER);

        // Create JWT
        $jwtConfig = Configuration::forSymmetricSigner(new Sha256(), InMemory::plainText($privateKey));
        $token = $jwtConfig->builder()
            ->issuedBy($issuer)
            ->permittedFor($clientId)
            ->relatedTo($clientId)
            ->getToken($jwtConfig->signer(), $jwtConfig->signingKey());

        return $token->toString();
    }

    /**
     * Please note that the DPOP _is not_ required when requesting a token to
     * authorize a client but the DPOP _is_ required when requesting an access
     * token.
     */

    public function generateAccessToken($clientId, $subject) {
        $issuer = $this->config->getServer()->get(OidcMeta::ISSUER);
        return [
            "header" => [],
            "payload" => [
                "iss" => $issuer,
                "aud" => "solid",
                "sub" => $subject,
                "exp" => time()+3600,
                "iat" => time(),
                "jti" => $this->generateJti(),
                "client_id" => $clientId,
                "webid" => $subject
            ]
        ];
    }

    public function bindDpop($dpop, $accessToken) {
        $jkt = $this->makeJwkThumbprint($dpop);
        $accessToken['payload']['cnf'] = [
            'jkt' => $jkt
        ];
        return $accessToken;
    }

    public function generateIdToken($clientId, $subject) {
        $issuer = $this->config->getServer()->get(OidcMeta::ISSUER);

        return [
            "header" => [],
            "payload" => [
                "iss" => $issuer,
                "aud" => $clientId,
                "azp" => $clientId,
                "sub" => $subject,
                "exp" => time()+3600,
                "iat" => time(),
                "jti" => $this->generateJti(),
            ]
        ];
    }

    public function bindCode($code, $idToken) {
        $tokenHash = $this->generateTokenHash($code);
        $idToken['payload']['c_hash'] = $tokenHash;
        return $idToken;
    }

    public function bindAccessToken($accessToken, $idToken) {
        $tokenHash = $this->generateTokenHash($accessToken);
        $idToken['payload']['at_hash'] = $tokenHash;
        return $idToken;
    }

    public function signToken($token) {
        $jwks = $this->getJwks();
        $token['header']['alg'] = "RS256";
        $token['header']['kid'] = $jwks['keys'][0]['kid']; // FIXME: Use the kid from the privateKey we are signing with;

        $header = Base64Url::encode(json_encode($token['header']));
        $payload = Base64Url::encode(json_encode($token['payload']));

        $signature = '';
        $key = $this->config->getKeys()->getPrivateKey()->getKeyContents();

        $signingKey = openssl_pkey_get_private($key);
        openssl_sign("$header.$payload", $signature, $signingKey, OPENSSL_ALGO_SHA256);
        $signature = Base64Url::encode($signature);

        $jwt = "$header.$payload.$signature";
        return $jwt;
    }

    public function respondToRegistration($registration, $privateKey) {
        /*
            Expects in $registration:
            client_id
            client_id_issued_at
            redirect_uris
            registration_client_uri
        */
        $registration_access_token = $this->generateRegistrationAccessToken($registration['client_id'], $privateKey);

        $registrationBase = array(
            'response_types' => array("id_token token"),
            'grant_types' => array("implicit"),
            'application_type' => 'web',
            'id_token_signed_response_alg' => "RS256",
            'token_endpoint_auth_method' => 'client_secret_basic',
            'registration_access_token' => $registration_access_token,
        );

        return array_merge($registrationBase, $registration);
    }

    public function addIdTokenToResponse($response, $clientId, $subject, $nonce, $privateKey, $dpop=null) {
        if ($response->hasHeader("Location")) {
            $value = $response->getHeaderLine("Location");
            if (preg_match("/#access_token=(.*?)&/", $value, $matches)) {
                $idToken = $this->generateIdToken($clientId, $subject);
                $idToken = $this->bindAccessToken($matches[1], $idToken);
                $idToken = $this->signToken($idToken);
                $value = preg_replace("/#access_token=(.*?)&/", "#access_token=\$1&id_token=$idToken&", $value);
                $response = $response->withHeader("Location", $value);
            } else if (preg_match("/code=(.*?)&/", $value, $matches)) {
                $idToken = $this->generateIdToken($clientId, $subject);
                $idToken = $this->bindCode($matches[1], $idToken);
                $idToken = $this->signToken($idToken);
                $value = preg_replace("/code=(.*?)&/", "code=\$1&id_token=$idToken&", $value);
                $response = $response->withHeader("Location", $value);
            }
        } else {
            $response->getBody()->rewind();
            $responseBody = $response->getBody()->getContents();
            try {
                $body = json_decode($responseBody, true);

                $accessToken = $this->generateAccessToken($clientId, $subject);
                $accessToken = $this->bindDpop($dpop, $accessToken);
                $accessToken = $this->signToken($accessToken);

                $idToken = $this->generateIdToken($clientId, $subject);
                $idToken = $this->bindAccessToken($accessToken, $idToken);
                $idToken = $this->signToken($idToken);

                $body['access_token'] = $accessToken;
                $body['id_token'] = $idToken;
                $body['refresh_token'] = str_repeat('a', 209); // FIXME: Remove this, DO NOT MERGE. Podpro doesn't like refresh tokens longer than 209 characters;

                return new JsonResponse($body);
            } catch (\Exception $e) {
                // leave the response as it was;
            }
        }
        return $response;
    }

    public function getCodeInfo($code) {
        return json_decode($this->decrypt($code), true);
    }

    ///////////////////////////// HELPER FUNCTIONS \\\\\\\\\\\\\\\\\\\\\\\\\\\\\

    private function generateJti() {
        return substr(md5((string)time()), 12); // FIXME: generate unique jti values
    }

    private function generateTokenHash($accessToken) {
        $atHash = hash('sha256', $accessToken);
        $atHash = substr($atHash, 0, 32);
        $atHash = hex2bin($atHash);
        $atHash = Base64Url::encode($atHash);
        return $atHash;
    }

    private function makeJwkThumbprint($dpop): string
    {
        $dpopConfig = Configuration::forUnsecuredSigner();
        $parsedDpop = $dpopConfig->parser()->parse($dpop);
        $jwk = $parsedDpop->headers()->get("jwk");

        if (empty($jwk)) {
            throw new InvalidTokenException('Required JWK header missing in DPOP');
        }

        return $this->dpopUtil->makeJwkThumbprint($jwk);
    }

    private function getJwks() {
        $key = $this->config->getKeys()->getPublicKey();
        $jwks = new Jwks($key);
        return json_decode((string) $jwks, true);
    }
}
