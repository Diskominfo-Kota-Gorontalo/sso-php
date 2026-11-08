<?php

declare(strict_types=1);

namespace Gorontalokota\Sso\Exception;

/**
 * A JWT (ID token, access token, or logout token) failed verification.
 */
class TokenValidationException extends SsoException
{
}
