<?php

// =============================================================================
// The majority of this part of the code is usually handled by your framework
// -----------------------------------------------------------------------------
session_start();
ob_start();

require_once __DIR__ . '/../vendor/autoload.php';

/*/ The PSR Request and Response objects are usually provided by your framework /*/
$request = \Laminas\Diactoros\ServerRequestFactory::fromGlobals($_SERVER, $_GET, $_POST, $_COOKIE, $_FILES);
$response = new \Laminas\Diactoros\Response();

/*/ The User (ID) is usually also provided by an entity in your framework /*/
$userId = $_SESSION['user_id'] ?? '';

/*/ An identifier for the requesting client is needed to ask your framework for information /*/
$clientIdentifier = \array_key_exists(\Pdsinterop\Solid\Auth\Enum\OAuth2\Parameter::CLIENT_ID,
    $request->getQueryParams())
    ? $request->getQueryParams()[\Pdsinterop\Solid\Auth\Enum\OAuth2\Parameter::CLIENT_ID]
    : '';

/*/ These should come from a database, based on $clientIdentifier
 *
 * They have previously been provided to or by the Client, using a Dynamic
 * Registration request.
/*/
$clientName = 'Example Client Name';
$clientRedirectUris = [
    'https://server/client/redirect-url',
    'https://server/client/another-redirect-url',
];
$clientSecret = 'client secret';
// =============================================================================


// =============================================================================
// Create the Authorization Server
// -----------------------------------------------------------------------------
$keyPath = dirname(__DIR__) . '/tests/fixtures/keys';
$encryptionKey = file_get_contents($keyPath . '/encryption.key');
$privateKey = file_get_contents($keyPath . '/private.key');
$publicKey = file_get_contents($keyPath . '/public.key');

$config = (new \Pdsinterop\Solid\Auth\Factory\ConfigFactory(
    new \Pdsinterop\Solid\Auth\Config\Client(
        $clientIdentifier,
        $clientSecret,
        $clientRedirectUris,
        $clientName
    ),
    $encryptionKey,$privateKey, $publicKey,
    [
        /* URL of the OP's OAuth 2.0 Authorization Endpoint [OpenID.Core]. */
        \Pdsinterop\Solid\Auth\Enum\OpenId\OpenIdConnectMetadata::AUTHORIZATION_ENDPOINT => 'https://server/authorize',

        /* URL using the https scheme with no query or fragment component that
         * the OP asserts as its Issuer Identifier. If Issuer discovery is
         * supported, this value MUST be identical to the issuer value returned
         * by WebFinger. This also MUST be identical to the iss Claim value in
         * ID Tokens issued from this Issuer.
         */
        \Pdsinterop\Solid\Auth\Enum\OpenId\OpenIdConnectMetadata::ISSUER => 'https://server/identifier',

        /* URL of the OP's JSON Web Key Set [JWK] document. This contains the
         * signing key(s) the RP uses to validate signatures from the OP. The
         * JWK Set MAY also contain the Server's encryption key(s), which are
         * used by RPs to encrypt requests to the Server.
         *
         * When both signing and encryption keys are made available, a use
         * (Key Use) parameter value is REQUIRED for all keys in the referenced
         * JWK Set to indicate each key's intended usage. Although some
         * algorithms allow the same key to be used for both signatures and
         *  encryption, doing so is NOT RECOMMENDED, as it is less secure.
         *
         * The JWK x5c parameter MAY be used to provide X.509 representations
         * of keys provided. When used, the bare key values MUST still be
         * present and MUST match those in the certificate.
         */
        \Pdsinterop\Solid\Auth\Enum\OpenId\OpenIdConnectMetadata::JWKS_URI => 'https://server/.well-known/jwks.json'
    ]
))->create();

$authorizationServer = (new \Pdsinterop\Solid\Auth\Factory\AuthorizationServerFactory($config))->create();

$user = null;
if ($userId !== '') {
    $user = new \Pdsinterop\Solid\Auth\Entity\User();
    $user->setIdentifier($userId);
}

$server = new \Pdsinterop\Solid\Auth\Server($authorizationServer, $config, $response);
// =============================================================================


// =============================================================================
// Handle requests
// -----------------------------------------------------------------------------
switch ($request->getMethod() . $request->getRequestTarget()) {
    case 'GET/.well-known/jwks.json':
        $response = $server->respondToJwksMetadataRequest();
        break;

    case 'GET/.well-known/openid-configuration':
        $response = $server->respondToOpenIdMetadataRequest();
        break;

    case 'POST/access_token':
        $response = $server->respondToAccessTokenRequest($request);
        break;

    case 'GET/authorize':
    case 'POST/authorize':
        /*/
         * The HTTP request is validate on every call.
         *
         * There are three steps to the Authorization request/response cycle:
         *
         * 1. Redirect the user to a login endpoint
         *    - The user logs in
         *
         * 2. Redirect the user to an authorization page
         *    - The user gives authorization to a client for certain scopes
         *
         * 3. Redirect the user to the URL provided by the Client
         *    - The user is returned to the client
         *
         * The returned response depends on the given parameters.
         *
         * A callback can be given to receive the AuthorizationRequest, for
         * instance to saves the serialized object into the user's session or
         * to read/compare state, scope, or other values.
         *
         * Please note that this callback is called _after_ any logic that runs
         * to create the response
        /*/
        $callback = static function (\League\OAuth2\Server\RequestTypes\AuthorizationRequest $authRequest) {
            if (empty($_SESSION['authRequest'])) {
                $_SESSION['authRequest'] = serialize($authRequest);
            }

            /** @var \League\OAuth2\Server\RequestTypes\AuthorizationRequest $sessionAuthRequest */
            $sessionAuthRequest = unserialize($_SESSION['authRequest'], \League\OAuth2\Server\RequestTypes\AuthorizationRequest::class);

            if ($authRequest->getState() !== $sessionAuthRequest->getState()) {
                throw new \UnexpectedValueException('Auth state does not match session state!');
            }
        };

        /*/ Step 1: The user is redirected to a login endpoint
         *
         * As the user is not yet logged in, no $user Entity object is provided.
         *
         * As the user has not yet approved (or denied) the Authorization
         * request, no approval status is given.
         *
         *      $response = $server->respondToAuthorizationRequest($request, null, null, $callback);
        /*/

        /*/ Step 2: The user is redirected to an authorization page
         *
         * As the user is now logged in, a $user Entity object is provided.
         *
         * As the user has not yet approved (or denied) the Authorization
         * request, no approval status is given.
         *
         *      $response = $server->respondToAuthorizationRequest($request, $user, null, $callback);
        /*/

        /*/ Step 3: The user is redirected to the URL provided by the Client
         *
         * As the user is now logged in, a $user Entity object _can_ be provided.
         *
         * As the user has now approved (or denied) the Authorization request,
         * an approval status is given.
         *
         * This is usually the user's response to a form asking them to approve
         * scopes requested by the client. If previous consent has been given,
         * this response _may_ come from the database without asking the user
         * again, in which case the form can be skipped completely.
         *
         * If other scopes are requested than those that have been stored, the
         * user will have to be asked to expand their permission to include the
         * new scopes.
         *
         *      $approval = Pdsinterop\Solid\Auth\Enum\Authorization::DENIED || $approval = Pdsinterop\Solid\Auth\Enum\Authorization::APPROVED;
         *      $response = $server->respondToAuthorizationRequest($request, null, $approval, $callback);
        /*/
        $approval = null; // <-- Change this in this example to emulate a user approving (or denying) the request
        $response = $server->respondToAuthorizationRequest($request, $user, $approval, $callback);
        break;

    case 'GET/.well-known/jwks.json':
        $response = $server->respondToJwksRequest();
        break;

    default:
        $response->getBody()->write('404');
        $response = $response->withStatus(404);
        break;
}
// =============================================================================


// =============================================================================
// Handling the response is usually also handled by your framework
// -----------------------------------------------------------------------------
foreach ($response->getHeaders() as $name => $values) {
    foreach ($values as $value) {
        header(sprintf('%s: %s', $name, $value), false);
    }
}

echo (string)  $response->getBody();
exit;
// =============================================================================
