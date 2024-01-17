<?php declare(strict_types=1);

namespace Pdsinterop\Solid\Auth\Utils;

use DateInterval;
use Exception;
use Jose\Component\Core\JWK;
use Jose\Component\Core\Util\ECKey;
use Jose\Component\Core\Util\RSAKey;
use Lcobucci\Clock\SystemClock;
use Lcobucci\JWT\Configuration;
use Lcobucci\JWT\Signer\Ecdsa\Sha256;
use Lcobucci\JWT\Signer\Key\InMemory;
use Lcobucci\JWT\Token\InvalidTokenStructure;
use Lcobucci\JWT\Validation\Constraint\LooseValidAt;
use Lcobucci\JWT\Validation\Constraint\SignedWith;
use Lcobucci\JWT\Validation\RequiredConstraintsViolated;
use Pdsinterop\Solid\Auth\Exception\AuthorizationHeaderException;
use Pdsinterop\Solid\Auth\Exception\InvalidTokenException;
use Psr\Http\Message\ServerRequestInterface;

/**
 * This class contains code to fetch the WebId from a request
 * that is make in legacy mode (bearer token with pop)
 *
 * @ TODO: Make sure this code complies with the spec and validate the tokens properly;
 * https://datatracker.ietf.org/doc/html/rfc7800
 */
class Bearer {

    private JtiValidator $jtiValidator;

	public function __construct(JtiValidator $jtiValidator)
	{
		$this->jtiValidator = $jtiValidator;
	}

	/**
	 * This method fetches the WebId from a request and verifies
	 * that the request has a valid pop token that matches
	 * the access token.
	 *
	 * @param ServerRequestInterface $request Server Request
	 *
	 * @return string the WebId, or "public" if no WebId is found
	 *
	 * @throws Exception "Invalid token" when the pop token is invalid
	 */
	public function getWebId($request) {
		$serverParams = $request->getServerParams();

		if (empty($serverParams['HTTP_AUTHORIZATION'])) {
			$webId = "public";
		} else {
			$this->validateRequestHeaders($serverParams);

			[, $jwt] = explode(" ", $serverParams['HTTP_AUTHORIZATION'], 2);

			try {
				$this->validateJwt($jwt, $request);
			} catch (RequiredConstraintsViolated $e) {
				throw new InvalidTokenException($e->getMessage(), 0, $e);
			}
			$idToken = $this->getIdTokenFromJwt($jwt);

			try {
				$this->validateIdToken($idToken, $request);
			} catch (RequiredConstraintsViolated $e) {
				throw new InvalidTokenException($e->getMessage(), 0, $e);
			}
			$webId = $this->getSubjectFromIdToken($idToken);
		}

		return $webId;
	}

	/**
	 * @param  string $jwt  JWT access token, raw
	 * @param  ServerRequestInterface $request Server Request
	 * @return bool
	 *
	 * FIXME: Add more validations to the token;
	 */
	public function validateJwt($jwt, $request) {
		$jwtConfig = Configuration::forUnsecuredSigner();
		$jwtConfig->parser()->parse($jwt);
		return true;
	}

	/**
	 * validates that the provided OIDC ID Token
	 * @param  string $token The OIDS ID Token (raw)
	 * @param  ServerRequestInterface $request Server Request
	 * @return bool          True if the id token is valid
	 * @throws InvalidTokenException when the tokens is not valid
	 *
	 * FIXME: Add more validations to the token;
	 */
	public function validateIdToken($token, $request) {
		$jwtConfig = Configuration::forUnsecuredSigner();
		$jwtConfig->parser()->parse($token);
		return true;
	}

	private function getIdTokenFromJwt($jwt) {
		$jwtConfig = Configuration::forUnsecuredSigner();
		try {
			$jwt = $jwtConfig->parser()->parse($jwt);
		} catch(Exception $e) {
			throw new InvalidTokenException("Invalid JWT token", 409, $e);
		}

		$idToken = $jwt->claims()->get("id_token");
		if ($idToken === null) {
			throw new InvalidTokenException('Missing "id_token"');
		}
		return $idToken;
	}

	private function getSubjectFromIdToken($idToken) {
		$jwtConfig = Configuration::forUnsecuredSigner();
		try {
			$jwt = $jwtConfig->parser()->parse($idToken);
		} catch(Exception $e) {
			throw new InvalidTokenException("Invalid ID token", 409, $e);
		}

		$sub = $jwt->claims()->get("sub");
		if ($sub === null) {
			throw new InvalidTokenException('Missing "sub"');
		}
		return $sub;
	}

	private function validateRequestHeaders($serverParams) {
		if (str_contains($serverParams['HTTP_AUTHORIZATION'], ' ') === false) {
			throw new AuthorizationHeaderException("Authorization Header does not contain parameters");
		}

		if (str_starts_with(strtolower($serverParams['HTTP_AUTHORIZATION']), 'bearer') === false) {
			throw new AuthorizationHeaderException('Only "bearer" authorization scheme is supported');
		}
	}
}
