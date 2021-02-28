<?php declare(strict_types=1);

namespace Pdsinterop\Solid\Auth\Utils;

use Lcobucci\JWT\Parser;
use Lcobucci\JWT\Signer\Key;
use Lcobucci\JWT\ValidationData;
use Jose\Component\Core\JWK;
use Jose\Component\Core\Util\ECKey;
use Jose\Component\Core\Util\RSAKey;

class DPop {
	public function getWebId($request) {
		$auth = explode(" ", $request->getServerParams()['HTTP_AUTHORIZATION']);
		$jwt = $auth[1];

		if (strtolower($auth[0]) == "dpop") {
			$dpop = $request->getServerParams()['HTTP_DPOP'];
			if ($dpop) {
				$dpopKey = $this->getDpopKey($dpop, $request);
				if (!$this->validateJwtDpop($jwt, $dpopKey)) {
					throw new \Exception("Invalid token");
				}
			}
		}

		if ($jwt) {
			$webId = $this->getSubjectFromJwt($jwt);
		} else {
			$webId = "public";
		}

		return $webId;
	}

	public function getDpopKey($dpop, $request) {
		//error_log("11");
		$this->validateDpop($dpop, $request);
		//error_log("22");
		
		$parser = new \Lcobucci\JWT\Parser();
		// 1.  the string value is a well-formed JWT,
		$dpop = $parser->parse($dpop);
		$jwk = $dpop->getHeader("jwk");
		//error_log(print_r($jwk, true));
		
		return $jwk->kid;		
	}

	private function validateJwtDpop($jwt, $dpopKey) {
		$parser = new \Lcobucci\JWT\Parser();
		$jwt = $parser->parse($jwt);
		$cnf = $jwt->getClaim("cnf");
		
		if ($cnf->jkt == $dpopKey) {
			//error_log("dpopKey matches");
			return true;
		}
		//error_log("dpopKey mismatch");
		//error_log(print_r($cnf, true));
		//error_log($dpopKey);
		
		return false;
	}

	private function validateDpop($dpop, $request) {
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
		*/
		//error_log("1");

		$parser = new \Lcobucci\JWT\Parser();
		// 1.  the string value is a well-formed JWT,
		$dpop = $parser->parse($dpop);
		
		//error_log("2");
	    // 2.  all required claims are contained in the JWT,
		$htm = $dpop->getClaim("htm"); // http method
		$htu = $dpop->getClaim("htu"); // http uri
		$typ = $dpop->getHeader("typ");
		$alg = $dpop->getHeader("alg");

		//error_log("3");
		// 3.  the "typ" field in the header has the value "dpop+jwt",
		if ($typ != "dpop+jwt") {
			throw new \Exception("typ is not dpop+jwt");
		}

		//error_log("4");
		// 4.  the algorithm in the header of the JWT indicates an asymmetric 
		//	   digital signature algorithm, is not "none", is supported by the
		//	   application, and is deemed secure,   
		if ($alg == "none") {
			throw new \Exception("alg is none");
		}
		
		//error_log("5");
		// 5.  that the JWT is signed using the public key contained in the
		//     "jwk" header of the JWT,
		$jwk = $dpop->getHeader("jwk");
		$webTokenJwk = \Jose\Component\Core\JWK::createFromJson(json_encode($jwk));
		switch ($alg) {
			case "RS256":
				$pem = \Jose\Component\Core\Util\RSAKey::createFromJWK($webTokenJwk)->toPEM();
				$signer = new \Lcobucci\JWT\Signer\Rsa\Sha256();
			break;
			case "ES256":
				$pem = \Jose\Component\Core\Util\ECKey::convertToPEM($webTokenJwk);
				$signer = new \Lcobucci\JWT\Signer\Ecdsa\Sha256();
			break;
			default:
				throw new \Exception("unsupported algorithm");
			break;
		}
		$key = new \Lcobucci\JWT\Signer\Key($pem);
		if (!$dpop->verify($signer, $key)) {
			throw new \Exception("invalid signature");
		}
		
		//error_log("6");
		// 6.  the "htm" claim matches the HTTP method value of the HTTP request
		//	   in which the JWT was received (case-insensitive),
		if (strtolower($htm) != strtolower($request->getMethod())) {
			throw new \Exception("htm http method is invalid");
		}

		//error_log("7");
		// 7.  the "htu" claims matches the HTTP URI value for the HTTP request
		//     in which the JWT was received, ignoring any query and fragment
		// 	   parts,
		$requestedPath = (string)$request->getUri();
		$requestedPath = preg_replace("/[?#].*$/", "", $requestedPath);
		// FIXME: Remove this; it was disabled for testing with a server running on 443 internally but accessible on :444
		$htu = str_replace(":444", "", $htu);
		$requestedPath = str_replace(":444", "", $requestedPath);

		//error_log("REQUESTED HTU $htu");
		//error_log("REQUESTED PATH $requestedPath");
		if ($htu != $requestedPath) { 
			throw new \Exception("htu does not match requested path");
		}

		//error_log("8");
		// 8.  the token was issued within an acceptable timeframe (see Section 9.1), and
		$validationData = new ValidationData(); // It will use the current time to validate (iat, nbf and exp)
		if (!$dpop->validate($validationData)) {
			throw new \Exception("token timing is invalid");
		}

		// 9.  that, within a reasonable consideration of accuracy and resource utilization, a JWT with the same "jti" value has not been received previously (see Section 9.1).
		// FIXME: Check if we know the jti;
		//error_log("9");

		return true;
	}
	
	private function getSubjectFromJwt($jwt) {
		$parser = new \Lcobucci\JWT\Parser();
		try {
			$jwt = $parser->parse($jwt);
		} catch(\Exception $e) {
			return $this->server->getResponse()->withStatus(409, "Invalid JWT token");
		}

		$sub = $jwt->getClaim("sub");
		return $sub;
	}
}
