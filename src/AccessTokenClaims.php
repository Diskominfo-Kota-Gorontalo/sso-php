<?php

declare(strict_types=1);

namespace Gorontalokota\Sso;

/**
 * Claims of a verified bearer access token (for APIs / resource servers).
 */
final class AccessTokenClaims
{
    /**
     * @param  list<string>  $scopes
     * @param  array<string, mixed>  $claims
     */
    public function __construct(
        public readonly string $subject,
        public readonly string $clientId,
        public readonly array $scopes,
        public readonly ?Realm $realm,
        public readonly ?string $sessionId,
        public readonly int $expiresAt,
        public readonly array $claims,
    ) {}

    public function hasScope(string $scope): bool
    {
        return in_array($scope, $this->scopes, true);
    }
}
