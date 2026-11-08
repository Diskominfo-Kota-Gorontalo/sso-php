<?php

declare(strict_types=1);

namespace Gorontalokota\Sso\Exception;

/**
 * The callback state does not match the pending authorization request (possible CSRF or expired login).
 */
class InvalidStateException extends SsoException
{
}
