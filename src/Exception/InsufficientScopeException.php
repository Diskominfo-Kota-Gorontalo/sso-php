<?php

declare(strict_types=1);

namespace Gorontalokota\Sso\Exception;

/**
 * The access token is valid but lacks scopes required by the API.
 */
class InsufficientScopeException extends TokenValidationException
{
    /**
     * @param  list<string>  $missingScopes
     */
    public function __construct(public readonly array $missingScopes)
    {
        parent::__construct('Access token is missing required scope(s): '.implode(' ', $missingScopes));
    }
}
