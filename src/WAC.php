<?php declare(strict_types=1);

namespace Pdsinterop\Solid\Auth;

use Pdsinterop\Rdf\Enum\Format as Format;

class WAC {
	private $filesystem;
	private $baseUrl;
	private $basePath;

	public function __construct($filesystem) {
		$this->filesystem = $filesystem;
		$this->baseUrl = '';
		$this->basePath = '';
	}
	
	public function setBaseUrl($url) {
		$this->baseUrl = $url;
		$serverRequest = new \Laminas\Diactoros\ServerRequest(array(),array(), $url);
		$this->basePath = $serverRequest->getUri()->getPath();
	}

	public function addWACHeaders($request, $response, $webId) {
		$path = $request->getUri()->getPath();
		if ($this->basePath) {
			$path = str_replace($this->basePath, '', $path);
		}
		$userGrants = $this->getWACGrants($this->getUserGrants($path, $webId), $request->getUri());
		$publicGrants = $this->getWACGrants($this->getPublicGrants($path), $request->getUri());

		$wacHeaders = array();
		if ($userGrants) {
			$wacHeaders[] = "user=\"$userGrants\"";
		}
		if ($publicGrants) {
			$wacHeaders[] = "public=\"$publicGrants\"";
		}
		
		$response = $response->withHeader("Link", '<.acl>; rel="acl"');
		$response = $response->withHeader("WAC-Allow", implode(",", $wacHeaders));
		
		return $response;
	}
	
	/**
	 * Checks the requested filename (path+name) and user (webid) to see if the request
	 * is allowed to continue, according to the web acl
	 * see: https://github.com/solid/web-access-control-spec
	 */

	public function isAllowed($request, $webId, $origin=false) {
		$requestedGrants = $this->getRequestedGrants($request);
		$uri = $request->getUri();
		$parentUri = $this->getParentUri($uri);

		if (
			$this->isUserGranted($requestedGrants['resource'], $uri, $webId) &&
			$this->isUserGranted($requestedGrants['parent'], $parentUri, $webId) &&
			$this->isOriginGranted($requestedGrants['resource'], $uri, $origin) &&
			$this->isOriginGranted($requestedGrants['parent'], $parentUri, $origin)
		) {
			return true;
		}
		return false;
	}

	private function isUserGranted($requestedGrants, $uri, $webId) {
		if (!$requestedGrants) {
			return true;
		}
		
		$path = $uri->getPath();
		if ($this->basePath) {
			$path = str_replace($this->basePath, '', $path);
		}

		// error_log("REQUESTED GRANT: " . join(" or ", $requestedGrants) . " on $uri");
		$grants = $this->getUserGrants($path, $webId);
		// error_log("GRANTED GRANTS for $webId: " . json_encode($grants));
		if (is_array($grants)) {
			foreach ($requestedGrants as $requestedGrant) {
				if ($grants['accessTo'] && $grants['accessTo'][$requestedGrant] && $this->arePathsEqual($grants['accessTo'][$requestedGrant], $uri)) {
					return true;
				} else if ($grants['default'][$requestedGrant]) {
					if ($this->arePathsEqual($grants['default'][$requestedGrant], $uri)) {
						return false; // only use default for children, not for an exact match;
					}
					return true;
				}
			}
		}
		return false;
	}
	
	private function isOriginGranted($requestedGrants, $uri, $origin) {
		if (!$requestedGrants) {
			return true;
		}
		if (!$origin) {
			return true;
		}
		if (strstr($this->baseUrl, $origin)) {
			// check if the origin is the same as the baseUrl origin,
			// if so this request is coming from ourselves.
			return true;
		}
		$path = $uri->getPath();
		if ($this->basePath) {
			$path = str_replace($this->basePath, '', $path);
		}

		//error_log("REQUESTED GRANT: " . join(" or ", $requestedGrants) . " on $uri");
		$grants = $this->getOriginGrants($path, $origin);
		//error_log("GRANTED GRANTS for $origin: " . json_encode($grants));
		if (is_array($grants)) {
			foreach ($requestedGrants as $requestedGrant) {
				if ($grants['accessTo'] && $grants['accessTo'][$requestedGrant] && $this->arePathsEqual($grants['accessTo'][$requestedGrant], $uri)) {
					return true;
				} else if ($grants['default'][$requestedGrant]) {
					if ($this->arePathsEqual($grants['default'][$requestedGrant], $uri)) {
						return false; // only use default for children, not for an exact match;
					}
					return true;
				}
			}
		}
		return false;
	}

	private function getUserGrants($resourcePath, $webId) {
		$aclPath = $this->getAclPath($resourcePath);
		if (!$aclPath) {
			return array();
		}
		$acl = $this->filesystem->read($aclPath);

		$graph = new \EasyRdf_Graph();
		$graph->parse($acl, Format::TURTLE, $this->getAclBase($aclPath));
		
		// error_log("GET GRANTS for $webId");

		$grants = $this->getPublicGrants($resourcePath);

		$matching = $graph->resourcesMatching('http://www.w3.org/ns/auth/acl#agent');
		//error_log("MATCHING " . sizeof($matching));
		// Find all grants machting our webId;
		foreach ($matching as $match) {
			$agent = $match->get("<http://www.w3.org/ns/auth/acl#agent>");
			if ($agent == $webId) {
				$accessTo = $match->get("<http://www.w3.org/ns/auth/acl#accessTo>");
				//error_log("$webId accessTo $accessTo");
				$default = $match->get("<http://www.w3.org/ns/auth/acl#default>");
				$modes = $match->all("<http://www.w3.org/ns/auth/acl#mode>");
				if ($default) {
					foreach ($modes as $mode) {
						$grants["default"][$mode->getUri()] = $default->getUri();
					}
				}
				if ($accessTo) {
					foreach ($modes as $mode) {
						$grants["accessTo"][$mode->getUri()] = $accessTo->getUri();
					}
				}
			}
		}

		return $grants;
	}

	private function getOriginGrants($resourcePath, $origin) {
		$aclPath = $this->getAclPath($resourcePath);
		if (!$aclPath) {
			return array();
		}
		$acl = $this->filesystem->read($aclPath);

		$graph = new \EasyRdf_Graph();
		$graph->parse($acl, Format::TURTLE, $this->getAclBase($aclPath));

		// error_log("GET GRANTS for $origin");

		$grants = $this->getPublicGrants($resourcePath);

		$matching = $graph->resourcesMatching('http://www.w3.org/ns/auth/acl#origin');
		//error_log("MATCHING " . sizeof($matching));
		// Find all grants machting our origin;
		foreach ($matching as $match) {
			$grantedOrigin = $match->get("<http://www.w3.org/ns/auth/acl#origin>");
			if ($grantedOrigin == $origin) {
				$accessTo = $match->get("<http://www.w3.org/ns/auth/acl#accessTo>");
				//error_log("$origin accessTo $accessTo");
				$default = $match->get("<http://www.w3.org/ns/auth/acl#default>");
				$modes = $match->all("<http://www.w3.org/ns/auth/acl#mode>");
				if ($default) {
					foreach ($modes as $mode) {
						$grants["default"][$mode->getUri()] = $default->getUri();
					}
				}
				if ($accessTo) {
					foreach ($modes as $mode) {
						$grants["accessTo"][$mode->getUri()] = $accessTo->getUri();
					}
				}
			}
		}

		return $grants;
	}

	private function getAclPath($path) {
		$path = $this->normalizePath($path);
		// get the filename from the request
		$filename = basename($path);
		$path = dirname($path);
		
		// error_log("REQUESTED PATH: $path");
		// error_log("REQUESTED FILE: $filename");

		$aclOptions = array(
			$this->normalizePath($path.'/'.$filename.'.acl'),
			$this->normalizePath($path.'/'.$filename.'/.acl'),
			$this->normalizePath($path.'/.acl'),
		);

		foreach ($aclOptions as $aclPath) {
			if (
				$this->filesystem->has($aclPath)
			) {
				return $aclPath;
			}
		}

		//error_log("Seeking .acl from $path");
		// see: https://github.com/solid/web-access-control-spec#acl-inheritance-algorithm
		// check for acl:default predicate, if not found, continue searching up the directory tree
		return $this->getParentAcl($path);
	}
	private function normalizePath($path) {
		return preg_replace("|//|", "/", $path);
	}
	private function getParentAcl($path) {
		//error_log("GET PARENT ACL $path");
		if ($this->filesystem->has($path.'/.acl')) {
			//error_log("CHECKING ACL FILE ON $path/.acl");
			return $path . "/.acl";
		}
		$parent = dirname($path);
		if ($parent == $path) {
			return false;
		} else {
			return $this->getParentAcl($parent);
		}
	}

	public function getRequestedGrants($request) {
		$method = strtoupper($request->getMethod());
		$path = $request->getUri()->getPath();
		if ($this->basePath) {
			$path = str_replace($this->basePath, '', $path);
		}

		// Special case: restrict access to all .acl files.
		// Control is needed to do anything with them,
		// having Control allows all operations.
		if (preg_match('/.acl$/', $path)) {
			return array(
				"resource" => array('http://www.w3.org/ns/auth/acl#Control')
			);
		}

		switch ($method) {
			case "GET":
			case "HEAD":
				return array(
					"resource" => array('http://www.w3.org/ns/auth/acl#Read')
				);
			break;
			case "DELETE":
				return array(
					"resource" => array('http://www.w3.org/ns/auth/acl#Write')
				);
			break;
			case "PUT":
				if ($this->filesystem->has($path)) {
					$body = $request->getBody()->getContents();
					$request->getBody()->rewind();

					$existingFile = $this->filesystem->read($path);
					if (strpos($body, $existingFile) === 0) { // new file starts with the content of the old, so 'Append' grant wil suffice;
						return array(
							"resource" => array(
								'http://www.w3.org/ns/auth/acl#Write',
								'http://www.w3.org/ns/auth/acl#Append'
							)
						);
					} else {
						return array(
							"resource" => array('http://www.w3.org/ns/auth/acl#Write')
						);
					}
				} else {
					// FIXME: to add a new file, Append is needed on the parent container;
					return array(
						"resource" => array('http://www.w3.org/ns/auth/acl#Write'),
						"parent"   => array('http://www.w3.org/ns/auth/acl#Append', 'http://www.w3.org/ns/auth/acl#Write')
					);
				}
			break;
			case "POST":
				return array(
					"resource" => array(
						'http://www.w3.org/ns/auth/acl#Write', // We need 'append' for this, but because Write trumps Append, also allow it when we have Write;
						'http://www.w3.org/ns/auth/acl#Append'
					)
				);
			break;
			case "PATCH";
				$grants = array();
				$body = $request->getBody()->getContents();
				if (strstr($body, "DELETE")) {
					$grants[] = 'http://www.w3.org/ns/auth/acl#Write';
				}
				if (strstr($body, "INSERT")) {
					if ($this->filesystem->has($path)) {
						$grants[] = 'http://www.w3.org/ns/auth/acl#Append';
					}
					$grants[] = 'http://www.w3.org/ns/auth/acl#Write';
				}
				// error_log($body);
				$request->getBody()->rewind();
				if ($this->filesystem->has($path)) {
					return array(
						"resource" => $grants
					);
				} else {
					return array(
						"resource" => $grants,
						"parent"   => array('http://www.w3.org/ns/auth/acl#Append', 'http://www.w3.org/ns/auth/acl#Write')
					);
				}
			break;
		}
	}

	private function arePathsEqual($grantPath, $requestPath) {
		// error_log("COMPARING GRANTPATH: [" . $grantPath. "]");
		// error_log("COMPARING REQPATH: [" . $requestPath . "]");
		return $grantPath == $requestPath;
	}

	private function getParentUri($uri) {
		$path = $uri->getPath();
		if ($path == "/") {
			return $uri;
		}

		$parentPath = dirname($path) . '/';
		if ($this->filesystem->has(str_replace($this->basePath, '', $parentPath))) {
			return $uri->withPath($parentPath);
		} else {
			return $this->getParentUri($uri->withPath($parentPath));
		}
	}
	private function getWACGrants($grants, $uri) {
		$wacGrants = array();
		
		foreach ((array)$grants['accessTo'] as $grant => $grantedUri) {
			if ($this->arePathsEqual($grantedUri, $uri)) {
				$wacGrants[] = $this->grantToWac($grant);
			}
		}
		foreach ((array)$grants['default'] as $grant => $grantedUri) {
			if (!$this->arePathsEqual($grantedUri, $uri)) {
				$wacGrants[] = $this->grantToWac($grant);
			}
		}

		return implode(" ", $wacGrants);
	}
	private function grantToWac($grant) {
		return strtolower(explode("#", $grant)[1]); // http://www.w3.org/ns/auth/acl#Read => read
	}

	private function getAclBase($aclPath) {
		return $this->baseUrl . $this->normalizePath(dirname($aclPath) . "/");
	}
	private function getPublicGrants($resourcePath) {
		$aclPath = $this->getAclPath($resourcePath);
		if (!$aclPath) {
			return array();
		}
		
		$acl = $this->filesystem->read($aclPath);

		$graph = new \EasyRdf_Graph();

		// error_log("PARSE ACL from $aclPath with base " . $this->getAclBase($aclPath));
		$graph->parse($acl, Format::TURTLE, $this->getAclBase($aclPath));
		
		$grants = array();

		$foafAgent = "http://xmlns.com/foaf/0.1/Agent";
		$matching = $graph->resourcesMatching('http://www.w3.org/ns/auth/acl#agentClass');
		foreach ($matching as $match) {
			$agentClass = $match->get("<http://www.w3.org/ns/auth/acl#agentClass>");
			if ($agentClass == $foafAgent) {
				$accessTo = $match->get("<http://www.w3.org/ns/auth/acl#accessTo>");
				$default = $match->get("<http://www.w3.org/ns/auth/acl#default>");
				$modes = $match->all("<http://www.w3.org/ns/auth/acl#mode>");
				if ($default) {
					foreach ($modes as $mode) {
						$grants["default"][$mode->getUri()] = $default->getUri();
					}
				}
				if ($accessTo) {
					foreach ($modes as $mode) {
						$grants["accessTo"][$mode->getUri()] = $accessTo->getUri();
					}
				}
			}
		}
		return $grants;
	}	
}
