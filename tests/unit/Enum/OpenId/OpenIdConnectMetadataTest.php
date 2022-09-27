<?php

namespace Pdsinterop\Solid\Auth\Enum\OpenId;

use Pdsinterop\Solid\Auth\Enum\AbstractEnumTest as TestCase;

/**
 * @coversNothing
 */
class OpenIdConnectMetadataTest extends TestCase
{
    final public function getEnum() : OpenIdConnectMetadata
    {
        return new OpenIdConnectMetadata();
    }

    final public function getExpectedValues() : array
    {
        return [
            'acr_values_supported',
            'authorization_endpoint',
            'claim_types_supported',
            'claims_locales_supported',
            'claims_parameter_supported',
            'claims_supported',
            'code_challenge_methods_supported',
            'dpop_signing_alg_values_supported',
            'display_values_supported',
            'grant_types_supported',
            'id_token_encryption_alg_values_supported',
            'id_token_encryption_enc_values_supported',
            'id_token_signing_alg_values_supported',
            'issuer',
            'jwks_uri',
            'op_policy_uri',
            'op_tos_uri',
            'registration_endpoint',
            'request_object_encryption_alg_values_supported',
            'request_object_encryption_enc_values_supported',
            'request_object_signing_alg_values_supported',
            'request_parameter_supported',
            'request_uri_parameter_supported',
            'require_request_uri_registration',
            'response_modes_supported',
            'response_types_supported',
            'scopes_supported',
            'service_documentation',
            'subject_types_supported',
            'token_endpoint',
            'token_endpoint_auth_methods_supported',
            'token_endpoint_auth_signing_alg_values_supported',
            'ui_locales_supported',
            'userinfo_encryption_alg_values_supported',
            'userinfo_encryption_enc_values_supported',
            'userinfo_endpoint',
            'userinfo_signing_alg_values_supported',
            'token_types_supported',
            'check_session_iframe',
            'end_session_endpoint'
        ];
    }

    final public function getTestValue() : string
    {
        return OpenIdConnectMetadata::AUTHORIZATION_ENDPOINT;
    }
}
