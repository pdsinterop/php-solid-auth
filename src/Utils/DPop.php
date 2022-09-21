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
 * It also verifies that the request has a valid DPoP token
 * that matches the access token
 */
class DPop {

    private JtiValidator $jtiValidator;

    public function __construct(JtiValidator $jtiValidator)
    {
        $this->jtiValidator = $jtiValidator;
    }

	/**
	 * This method fetches the WebId from a request and verifies
	 * that the request has a valid DPoP token that matches
	 * the access token.
	 *
	 * @param ServerRequestInterface $request Server Request
	 *
	 * @return string the WebId, or "public" if no WebId is found
	 *
	 * @throws Exception "Invalid token" when the DPoP token is invalid
	 * @throws Exception "Missing DPoP token" when the DPoP token is missing, but the Authorisation header in the request specifies it
	 */
	public function getWebId($request) {
		$serverParams = $request->getServerParams();

		if (isset($serverParams['HTTP_AUTHORIZATION']) === false) {
			throw new AuthorizationHeaderException("Authorization Header missing");
		}

		if (str_contains($serverParams['HTTP_AUTHORIZATION'], ' ') === false) {
			throw new AuthorizationHeaderException("Authorization Header does not contain parameters");
		}

		[$authScheme, $jwt] = explode(" ", $serverParams['HTTP_AUTHORIZATION'], 2);
		$authScheme = strtolower($authScheme);

		if ($authScheme !== "dpop") {
			throw new AuthorizationHeaderException('Only "dpop" authorization scheme is supported');
		}

		if (isset($serverParams['HTTP_DPOP']) === false) {
			throw new AuthorizationHeaderException("Missing DPoP token");
		}

		$dpop = $serverParams['HTTP_DPOP'];

		//@FIXME: check that there is just one DPoP token in the request
		try {
			$dpopKey = $this->getDpopKey($dpop, $request);
		} catch (InvalidTokenStructure $e) {
			throw new InvalidTokenException("Invalid JWT token: {$e->getMessage()}", 0, $e);
		}

		try {
			$this->validateJwtDpop($jwt, $dpopKey);
		} catch (RequiredConstraintsViolated $e) {
			throw new InvalidTokenException($e->getMessage(), 0, $e);
		}

		if ($jwt) {
			$webId = $this->getSubjectFromJwt($jwt);
		} else {
			$webId = "public";
		}

		return $webId;
	}

	/**
	 * Returns the "kid" from the "jwk" header in the DPoP token.
	 * The DPoP token must be valid.
	 *
	 * @param string $dpop The DPoP token
	 * @param ServerRequestInterface $request Server Request
	 *
	 * @return string          the "kid" from the "jwk" header in the DPoP token.
	 *
	 * @throws RequiredConstraintsViolated
	 */
	public function getDpopKey($dpop, $request) {
		$this->validateDpop($dpop, $request);

		// 1.  the string value is a well-formed JWT,
		$jwtConfig = Configuration::forUnsecuredSigner();
		$dpop = $jwtConfig->parser()->parse($dpop);
		$jwk  = $dpop->headers()->get("jwk");

		if (isset($jwk['kid']) === false) {
			throw new InvalidTokenException('Key ID is missing from JWK header');
		}

		return $jwk['kid'];
	}

	private function validateJwtDpop($jwt, $dpopKey) {
		$jwtConfig = Configuration::forUnsecuredSigner();
		$jwt = $jwtConfig->parser()->parse($jwt);
		$cnf = $jwt->claims()->get("cnf");

		if ($cnf === null) {
			throw new InvalidTokenException('JWT Confirmation claim (cnf) is missing');
		}

		if (isset($cnf['jkt']) === false) {
			throw new InvalidTokenException('JWT Confirmation claim (cnf) is missing Thumbprint (jkt)');
		}

		if ($cnf['jkt'] !== $dpopKey) {
			throw new InvalidTokenException('JWT Confirmation claim (cnf) provided Thumbprint (jkt) does not match Key ID from JWK header');
		}

		//@FIXME: add check for "ath" claim in DPoP token, per https://datatracker.ietf.org/doc/html/draft-ietf-oauth-dpop#section-7
		return false;
	}

	/**
	 * Validates that the DPOP token matches all requirements from 
	 * https://datatracker.ietf.org/doc/html/draft-ietf-oauth-dpop#section-4.2
	 *
	 * @param string $dpop The DPOP token
	 * @param ServerRequestInterface $request Server Request
	 *
	 * @return bool True if the DPOP token is valid, false otherwise
	 *
	 * @throws RequiredConstraintsViolated
	 */
	public function validateDpop($dpop, $request) {
		/*
			4.2.  Checking DPoP Proofs
			   To check if a string that was received as part of an HTTP Request is
			   a valid DPoP proof, the receiving server MUST ensure that
			   1.  the string value is a well-formed JWT,
			   2.  all required claims are contained in the JWT,
			   3.  the "typ" field in the header has the value "dpop+jwt",
			   4.  the algorithm in the header of the JWT indicates an asymmetric
				   digital signature algorithm, is not "none", is supported by the
				   application, and is deemed secure,
			   5.  that the JWT is signed using the public key contained in the
				   "jwk" header of the JWT,
			   6.  the "htm" claim matches the HTTP method value of the HTTP request
				   in which the JWT was received (case-insensitive),
			   7.  the "htu" claims matches the HTTP URI value for the HTTP request
				   in which the JWT was received, ignoring any query and fragment
				   parts,
			   8.  the token was issued within an acceptable timeframe (see
				   Section 9.1), and
			   9.  that, within a reasonable consideration of accuracy and resource
				   utilization, a JWT with the same "jti" value has not been
				   received previously (see Section 9.1).
			  10.  that, if used with an access token, it also contains the 'ath' 
			       claim, with a hash of the access token
		*/
		// 1.  the string value is a well-formed JWT,
		$jwtConfig = Configuration::forUnsecuredSigner();
		$dpop = $jwtConfig->parser()->parse($dpop);

	    // 2.  all required claims are contained in the JWT,
		$htm = $dpop->claims()->get("htm"); // http method
		if (!$htm) {
			throw new InvalidTokenException("missing htm");
		}
		$htu = $dpop->claims()->get("htu"); // http uri
		if (!$htu) {
			throw new InvalidTokenException("missing htu");
		}
		$typ = $dpop->headers()->get("typ");
		if (!$typ) {
			throw new InvalidTokenException("missing typ");
		}
		$alg = $dpop->headers()->get("alg");
		if (!$alg) {
			throw new InvalidTokenException("missing alg");
		}

		// 3.  the "typ" field in the header has the value "dpop+jwt",
		if ($typ != "dpop+jwt") {
			throw new InvalidTokenException("typ is not dpop+jwt");
		}

		// 4.  the algorithm in the header of the JWT indicates an asymmetric 
		//	   digital signature algorithm, is not "none", is supported by the
		//	   application, and is deemed secure,   
		if ($alg == "none") {
			throw new InvalidTokenException("alg is none");
		}

		// 5.  that the JWT is signed using the public key contained in the
		//     "jwk" header of the JWT,
		$jwk = $dpop->headers()->get("jwk");
		$webTokenJwk = JWK::createFromJson(json_encode($jwk));
		switch ($alg) {
			case "RS256":
				$pem = RSAKey::createFromJWK($webTokenJwk)->toPEM();
				$signer = new \Lcobucci\JWT\Signer\Rsa\Sha256();
			break;
			case "ES256":
				$pem = ECKey::convertToPEM($webTokenJwk);
                $signer = Sha256::create();
			break;
			default:
				throw new InvalidTokenException("unsupported algorithm");
			break;
		}
		$key = InMemory::plainText($pem);
		$validationConstraints = [];
		$validationConstraints[] = new SignedWith($signer, $key);

		// 6.  the "htm" claim matches the HTTP method value of the HTTP request
		//	   in which the JWT was received (case-insensitive),
		if (strtolower($htm) != strtolower($request->getMethod())) {
			throw new InvalidTokenException("htm http method is invalid");
		}

		// 7.  the "htu" claims matches the HTTP URI value for the HTTP request
		//     in which the JWT was received, ignoring any query and fragment
		// 	   parts,
		$requestedPath = (string)$request->getUri();
		$requestedPath = preg_replace("/[?#].*$/", "", $requestedPath);

		//error_log("REQUESTED HTU $htu");
		//error_log("REQUESTED PATH $requestedPath");
		if ($htu != $requestedPath) { 
			throw new InvalidTokenException("htu does not match requested path");
		}

		// 8.  the token was issued within an acceptable timeframe (see Section 9.1), and

		$leeway = new DateInterval("PT60S"); // allow 60 seconds clock skew
		$clock = SystemClock::fromUTC();
		$validationConstraints[] = new LooseValidAt($clock, $leeway); // It will use the current time to validate (iat, nbf and exp)
		if (!$jwtConfig->validator()->validate($dpop, ...$validationConstraints)) {
			$jwtConfig->validator()->assert($dpop, ...$validationConstraints); // throws an explanatory exception
		}

		// 9.  that, within a reasonable consideration of accuracy and resource utilization, a JWT with the same "jti" value has not been received previously (see Section 9.1).
		$jti = $dpop->claims()->get("jti");
		if ($jti === null) {
			throw new InvalidTokenException("jti is missing");
		}
		$isJtiValid = $this->jtiValidator->validate($jti, (string) $request->getUri());
		if (! $isJtiValid) {
			throw new InvalidTokenException("jti is invalid");
		}

		// 10. that, if used with an access token, it also contains the 'ath' claim, with a hash of the access token
		// TODO: implement

		return true;
	}

	private function getSubjectFromJwt($jwt) {
		$jwtConfig = Configuration::forUnsecuredSigner();
		try {
			$jwt = $jwtConfig->parser()->parse($jwt);
		} catch(Exception $e) {
			throw new InvalidTokenException("Invalid JWT token", 409, $e);
		}

		$sub = $jwt->claims()->get("sub");
		if ($sub === null) {
			throw new InvalidTokenException('Missing "SUB"');
		}
		return $sub;
	}
}
