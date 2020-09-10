<?php declare(strict_types=1);

namespace Pdsinterop\Solid\Auth\Config;

class Client
{
    /** @var string */
    private $identifier;
    /** @var string */
    private $secret;

    public function getIdentifier() : string
    {
        return $this->identifier;
    }

    public function getSecret() : string
    {
        return $this->secret;
    }

    final public function __construct(string $identifier, string $secret)
    {
        $this->identifier = $identifier;
        $this->secret = $secret;
    }
}
