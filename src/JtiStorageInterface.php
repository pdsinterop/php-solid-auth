<?php

namespace Pdsinterop\Solid\Auth;

/**
 * This interface defines methods that a storage layer need to implement
 * in order to allow the JTI Service to validate JTI tokens.
 *
 * Such a token is a string between 12 and 256 characters of length.
 */
interface JtiStorageInterface
{
    /**
     * Store a given JTI for a given URI
     *
     * @param string|object $jti string or string-able object
     * @param string $targetUri
     *
     * @return void
     *
     * @throws \Exception When storage fails, any type of Exception might be thrown...
     */
    public function store(string|object $jti, string $targetUri): void;

    /**
     * Retrieve a given JTI for a given URI
     *
     * @param string|object $jti string or string-able object
     * @param string $targetUri
     *
     * @return bool
     *
     * @throws \Exception When retrieval fails, any type of Exception might be thrown...
     */
    public function retrieve(string|object $jti, string $targetUri): bool;

    /**
     * Create a new storage slot and discard the oldest slot
     *
     * @return void
     *
     * @throws \Exception When rotation fails, any type of Exception might be thrown...
     */
    public function rotateBuckets(): void;
}
