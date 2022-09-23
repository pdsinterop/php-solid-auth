<?php declare(strict_types=1);

namespace Pdsinterop\Solid\Auth;

use Pdsinterop\Solid\Auth\Utils\Jwks;
use Pdsinterop\Solid\Auth\Enum\OpenId\OpenIdConnectMetadata as OidcMeta;
use Laminas\Diactoros\Response\JsonResponse as JsonResponse;
use League\OAuth2\Server\CryptTrait;

use DateTimeImmutable;
use Lcobucci\JWT\Configuration;
use Lcobucci\JWT\Signer\Key\InMemory;
use Lcobucci\JWT\Signer\Rsa\Sha256;

class TokenGenerator
{
    ////////////////////////////// CLASS PROPERTIES \\\\\\\\\\\\\\\\\\\\\\\\\\\\

    use CryptTrait;

    public Config $config;

    private \DateInterval $validFor;

    //////////////////////////////// PUBLIC API \\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\

    final public function __construct(
        Config $config,
        \DateInterval $validFor
    ) {
        $this->config = $config;
        $this->validFor = $validFor;

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

	public function generateIdToken($accessToken, $clientId, $subject, $nonce, $privateKey, $dpopKey, $now=null) {
		$issuer = $this->config->getServer()->get(OidcMeta::ISSUER);

		$jwks = $this->getJwks();
		$tokenHash = $this->generateTokenHash($accessToken);

                // Create JWT
                $jwtConfig = Configuration::forSymmetricSigner(new Sha256(), InMemory::plainText($privateKey));
                $now = $now ?? new DateTimeImmutable();
                $useAfter = $now->sub(new \DateInterval('PT1S'));

                $expire = $now->add($this->validFor);

                $token = $jwtConfig->builder()
                        ->issuedBy($issuer)
                        ->permittedFor($clientId)
                        ->issuedAt($now)
                        ->canOnlyBeUsedAfter($useAfter)
                        ->expiresAt($expire)
                        ->withClaim("azp", $clientId)
                        ->relatedTo($subject)
                        ->identifiedBy($this->generateJti())
                        ->withClaim("nonce", $nonce)
                        ->withClaim("at_hash", $tokenHash) //FIXME: at_hash should only be added if the response_type is a token
                        ->withClaim("c_hash", $tokenHash) // FIXME: c_hash should only be added if the response_type is a code
                        ->withClaim("cnf", array(
                                "jkt" => $dpopKey,
                        //      "jwk" => $jwks['keys'][0]
                        ))
                        ->withHeader('kid', $jwks['keys'][0]['kid'])
                        ->getToken($jwtConfig->signer(), $jwtConfig->signingKey());
                return $token->toString();
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

	public function addIdTokenToResponse($response, $clientId, $subject, $nonce, $privateKey, $dpopKey=null) {
		if ($response->hasHeader("Location")) {
			$value = $response->getHeaderLine("Location");

			if (preg_match("/#access_token=(.*?)&/", $value, $matches)) {
				$idToken = $this->generateIdToken(
					$matches[1],
					$clientId,
					$subject,
					$nonce,
					$privateKey,
					$dpopKey
				);
				$value = preg_replace("/#access_token=(.*?)&/", "#access_token=\$1&id_token=$idToken&", $value);
				$response = $response->withHeader("Location", $value);
			} else if (preg_match("/code=(.*?)&/", $value, $matches)) {
				$idToken = $this->generateIdToken(
					$matches[1],
					$clientId,
					$subject,
					$nonce,
					$privateKey,
					$dpopKey
				);
				$value = preg_replace("/code=(.*?)&/", "code=\$1&id_token=$idToken&", $value);
				$response = $response->withHeader("Location", $value);
			}
		} else {
			$response->getBody()->rewind();
			$responseBody = $response->getBody()->getContents();
			try {
				$body = json_decode($responseBody, true);
				if (isset($body['access_token'])) {
					$body['id_token'] = $this->generateIdToken(
						$body['access_token'],
						$clientId,
						$subject,
						$nonce,
						$privateKey,
						$dpopKey
					);

					$body['access_token'] = $body['id_token'];
					return new JsonResponse($body);
				}
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
		$atHash = base64_encode($atHash);
		$atHash = rtrim($atHash, '=');
		$atHash = str_replace('/', '_', $atHash);
		$atHash = str_replace('+', '-', $atHash);

		return $atHash;
	}

	private function getJwks() {
        $key = $this->config->getKeys()->getPublicKey();
        $jwks = new Jwks($key);
		return json_decode($jwks->__toString(), true);
	}
}
