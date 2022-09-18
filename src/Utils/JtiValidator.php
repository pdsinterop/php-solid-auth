<?php

namespace Pdsinterop\Solid\Auth\Utils;

use DateInterval;
use Lcobucci\JWT\Token\InvalidTokenStructure;
use Pdsinterop\Solid\Auth\JtiStorageInterface;

/**
 * Validates whether a provided JTI (JWT ID) is valid.
 *
 * @see https://datatracker.ietf.org/doc/html/draft-ietf-oauth-dpop
 */
class JtiValidator
{
    ////////////////////////////// CLASS PROPERTIES \\\\\\\\\\\\\\\\\\\\\\\\\\\\

    /**
     * Maximum allowed amount of seconds a JTI is valid
     */
    private int $maxIntervalSeconds = 600; // @TODO: Time::MINUTES_10

    //////////////////////////////// PUBLIC API \\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\

    /**
     * @param JtiStorageInterface $jtiStorage
     * @param DateInterval $interval
     *
     * @throw \InvalidArgumentException When the provided Interval is not valid
     */
    final public function __construct(private JtiStorageInterface $jtiStorage, private DateInterval $interval)
    {
        $intervalSeconds = $this->interval->format('s');

        // @CHECKME: Is there a maximum validity period? Does the spec say anything about this?
        //           Or do we not need to check and should we just trust the user?
        // @FIXME: Use DateTime / DateInterval objects rather than math to compare times
        if ($intervalSeconds > $this->maxIntervalSeconds) {
            $message = vsprintf(
                'Given time interval (%s) is larger than the allowed maximum (%s)',
                [
                    'interval' => $intervalSeconds,
                    'maximum' => $this->maxIntervalSeconds,
                ]
            );

            throw new \InvalidArgumentException($message);
        }
    }

    public function validate($jti, $targetUri): bool
    {
        $isValid = false;

        $strlen = mb_strlen($jti);
        /* At least 96 bits of pseudorandom data are required,
         * which is 12 characters (or 24 hexadecimal characters)
         * The upper limit is chosen based on maximum field length in common database storage types (varchar)
         */
        if ($strlen > 12 && $strlen < 256) {
            $isValid = $this->jtiStorage->retrieve($jti, $targetUri) === false;

            if ($isValid === true) {
                // @CHECKME: Should we catch exceptions here? Catch them in the DPOP calll? Allow them to bubble up?
                $this->jtiStorage->store($jti, $targetUri);
            }

            // @CHECKME: Should rotation be checked before or after storing the JTI?
            if ($this->shouldRotate()) {
                $this->jtiStorage->rotateBuckets();
            }
        }

        return $isValid;
    }
    ////////////////////////////// UTILITY METHODS \\\\\\\\\\\\\\\\\\\\\\\\\\\\\
    private function shouldRotate(): bool
    {
        $shouldRotate = false;

        // @CHECKME: How to round of the interval? Count up from X:00 and add increments?
        //           This would basically be modulo?

        return $shouldRotate;
    }
}
