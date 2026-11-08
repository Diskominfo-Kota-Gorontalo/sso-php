<?php

declare(strict_types=1);

namespace Gorontalokota\Sso;

/**
 * Tokens returned by the token endpoint. Keep them server-side only (session or encrypted storage).
 */
final class TokenSet
{
    /**
     * @param  array<string, mixed>  $idTokenClaims  Verified ID token claims (empty when no ID token was returned).
     */
    public function __construct(
        public readonly string $accessToken,
        public readonly int $expiresAt,
        public readonly ?string $refreshToken = null,
        public readonly ?string $idToken = null,
        public readonly array $idTokenClaims = [],
        public readonly string $scope = '',
    ) {}

    public function isExpired(int $now, int $skew = 30): bool
    {
        return $now >= $this->expiresAt - $skew;
    }

    public function user(): ?SsoUser
    {
        return $this->idTokenClaims === [] ? null : SsoUser::fromClaims($this->idTokenClaims);
    }

    /**
     * @return list<string>
     */
    public function scopes(): array
    {
        return array_values(array_filter(explode(' ', $this->scope)));
    }

    /**
     * @return array{access_token: string, expires_at: int, refresh_token: string|null, id_token: string|null, id_token_claims: array<string, mixed>, scope: string}
     */
    public function toArray(): array
    {
        return [
            'access_token' => $this->accessToken,
            'expires_at' => $this->expiresAt,
            'refresh_token' => $this->refreshToken,
            'id_token' => $this->idToken,
            'id_token_claims' => $this->idTokenClaims,
            'scope' => $this->scope,
        ];
    }

    /**
     * @param  array<string, mixed>  $data
     */
    public static function fromArray(array $data): self
    {
        return new self(
            accessToken: (string) ($data['access_token'] ?? ''),
            expiresAt: (int) ($data['expires_at'] ?? 0),
            refreshToken: isset($data['refresh_token']) ? (string) $data['refresh_token'] : null,
            idToken: isset($data['id_token']) ? (string) $data['id_token'] : null,
            idTokenClaims: is_array($data['id_token_claims'] ?? null) ? $data['id_token_claims'] : [],
            scope: (string) ($data['scope'] ?? ''),
        );
    }
}
