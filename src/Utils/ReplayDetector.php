<?php

namespace Pdsinterop\Solid\Auth\Utils;

use DateInterval;
use Pdsinterop\Solid\Auth\ReplayDetectorInterface;

/**
 * Validates whether a provided JTI (JWT ID) is valid.
 *
 * @see https://datatracker.ietf.org/doc/html/draft-ietf-oauth-dpop
 */
class ReplayDetector implements ReplayDetectorInterface
{
    private $callback;
    
    public function __construct($callback) {
        $this->callback = $callback;
    }
    public function detect(string $jti, string $targetUri): bool
    {
        return ($this->callback)($jti, $targetUri);
    }
}
