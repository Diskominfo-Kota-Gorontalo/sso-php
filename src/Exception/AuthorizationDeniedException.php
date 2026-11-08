<?php

declare(strict_types=1);

namespace Gorontalokota\Sso\Exception;

/**
 * The user refused consent or the SSO returned an authorization error (?error=... on the callback).
 */
class AuthorizationDeniedException extends SsoException
{
    public function __construct(public readonly string $error, public readonly ?string $description = null)
    {
        parent::__construct($description !== null && $description !== '' ? "{$error}: {$description}" : $error);
    }
}
