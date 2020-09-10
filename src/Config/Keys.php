<?php declare(strict_types=1);

namespace Pdsinterop\Solid\Auth\Config;

use Defuse\Crypto\Key as CryptoKey;
use League\OAuth2\Server\CryptKey;

class Keys
{
    ////////////////////////////// CLASS PROPERTIES \\\\\\\\\\\\\\\\\\\\\\\\\\\\

    /** @var string|CryptoKey */
    private $encryptionKey;
    /** @var CryptKey*/
    private $privateKey;

    //////////////////////////// GETTERS AND SETTERS \\\\\\\\\\\\\\\\\\\\\\\\\\\

    /** @return CryptoKey|string */
    final public function getEncryptionKey()
    {
        return $this->encryptionKey;
    }

    /** @return CryptKey */
    final public function getPrivateKey() : CryptKey
    {
        return $this->privateKey;
    }

    //////////////////////////////// PUBLIC API \\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\

    /**
     * Keys constructor.
     *
     * @param CryptKey $privateKey
     * @param string|CryptoKey $encryptionKey
     */
    final public function __construct(CryptKey $privateKey, $encryptionKey)
    {
        // @FIXME: Add type-check for $encryptionKey (or an extending class with different parameter type?)
        $this->encryptionKey = $encryptionKey;
        $this->privateKey = $privateKey;
    }
}
