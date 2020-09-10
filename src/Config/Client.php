<?php declare(strict_types=1);

namespace Pdsinterop\Solid\Auth\Config;

class Client
{
    ////////////////////////////// CLASS PROPERTIES \\\\\\\\\\\\\\\\\\\\\\\\\\\\

    /** @var string */
    private $authorizationPageUrl;
    /** @var string */
    private $identifier;
    /** @var string */
    private $loginUrl;
    /** @var string */
    private $secret;

    //////////////////////////// GETTERS AND SETTERS \\\\\\\\\\\\\\\\\\\\\\\\\\\

    final public function getIdentifier() : string
    {
        return $this->identifier;
    }

    final public function getSecret() : string
    {
        return $this->secret;
    }

    final public function getAuthorizationPageUrl() : string
    {
        return $this->authorizationPageUrl;
    }

    final public function getLoginUrl() : string
    {
        return $this->loginUrl;
    }

    //////////////////////////////// PUBLIC API \\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\

    final public function __construct(string $identifier, string $secret, string $authorizationPageUrl = '', string $loginUrl = '')
    {
        $this->authorizationPageUrl = $authorizationPageUrl;
        $this->identifier = $identifier;
        $this->loginUrl = $loginUrl;
        $this->secret = $secret;
    }
}
