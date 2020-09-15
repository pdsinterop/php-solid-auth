<?php declare(strict_types=1);

namespace Pdsinterop\Solid\Auth\Factory;

use Lcobucci\JWT\Signer\Key;
use League\OAuth2\Server\CryptKey;
use Pdsinterop\Solid\Auth\Config;
use Pdsinterop\Solid\Auth\Enum\OAuth2\GrantType;
use Pdsinterop\Solid\Auth\Enum\Time;

class ConfigFactory
{
    /** @var string */
    private $clientIdentifier;
    /** @var string */
    private $clientSecret;
    /** @var string */
    private $encryptionKey;
    /** @var string */
    private $privateKey;
    /** @var string */
    private $publicKey;
    /** @var array */
    private $serverConfig;

    final public function __construct(
        string $clientIdentifier,
        string $clientSecret,
        string $encryptionKey,
        string $privateKey,
        string $publicKey,
        array $serverConfig
    ) {
        $this->clientIdentifier = $clientIdentifier;
        $this->clientSecret = $clientSecret;
        $this->encryptionKey = $encryptionKey;
        $this->privateKey = $privateKey;
        $this->serverConfig = $serverConfig;
        $this->publicKey = $publicKey;
    }

    final public function create() : Config
    {
        $clientIdentifier = $this->clientIdentifier;
        $clientSecret = $this->clientSecret;
        $encryptionKey = $this->encryptionKey;
        $privateKey = $this->privateKey;
        $publicKey = $this->publicKey;

        $client = new Config\Client($clientIdentifier, $clientSecret);

        $expiration = new Config\Expiration(Time::HOURS_1, Time::MINUTES_10, Time::MONTHS_1);

        $grantTypes = [
            GrantType::AUTH_CODE,
            GrantType::CLIENT_CREDENTIALS,
            GrantType::REFRESH_TOKEN,
        ];

        $keys = new Config\Keys(
            new CryptKey($privateKey),
            new Key($publicKey),
            $encryptionKey
        );

        $server = new Config\Server($this->serverConfig);

        return new Config(
            $client,
            $expiration,
            $grantTypes,
            $keys,
            $server
        );
    }
}
