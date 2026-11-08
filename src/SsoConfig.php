<?php

declare(strict_types=1);

namespace Gorontalokota\Sso;

use InvalidArgumentException;

/**
 * Client registration as configured in the SSO admin panel.
 */
final class SsoConfig
{
    /** @var list<string> */
    public readonly array $scopes;

    /** @var list<string> */
    public readonly array $audiences;

    /**
     * @param  string  $issuer  e.g. https://sso.gorontalokota.go.id/internal (see Realm::issuer()).
     * @param  string|null  $clientSecret  Null for public clients (PKCE only).
     * @param  list<string>  $scopes
     * @param  list<string>  $audiences  Accepted "aud" values when verifying bearer access tokens (defaults to the client id).
     * @param  int  $leeway  Clock skew tolerance in seconds.
     * @param  float  $httpTimeout  Seconds.
     */
    public function __construct(
        public readonly string $issuer,
        public readonly string $clientId,
        public readonly ?string $clientSecret = null,
        public readonly ?string $redirectUri = null,
        array $scopes = ['openid', 'profile', 'email'],
        public readonly ?string $postLogoutRedirectUri = null,
        array $audiences = [],
        public readonly int $leeway = 60,
        public readonly float $httpTimeout = 10.0,
    ) {
        if ($issuer === '' || $clientId === '') {
            throw new InvalidArgumentException('SSO issuer and client id are required.');
        }

        if (! str_starts_with($issuer, 'https://') && ! preg_match('#^http://(localhost|127\.0\.0\.1)(:\d+)?/#', $issuer.'/')) {
            throw new InvalidArgumentException('SSO issuer must use https (http is only allowed for localhost).');
        }

        $scopes = array_values(array_unique(array_map('strval', $scopes)));
        $this->scopes = in_array('openid', $scopes, true) ? $scopes : ['openid', ...$scopes];
        $this->audiences = $audiences === [] ? [$clientId] : array_map('strval', $audiences);
    }

    /**
     * @param  array{issuer?: string, realm?: string, base_url?: string, client_id?: string, client_secret?: string|null, redirect_uri?: string|null, scopes?: list<string>|string, post_logout_redirect_uri?: string|null, audiences?: list<string>|string, leeway?: int, http_timeout?: float}  $options
     */
    public static function fromArray(array $options): self
    {
        $issuer = $options['issuer'] ?? null;

        if (($issuer === null || $issuer === '') && isset($options['realm'])) {
            $issuer = Realm::from((string) $options['realm'])->issuer($options['base_url'] ?? Realm::DEFAULT_BASE_URL);
        }

        $list = static fn (array|string|null $value): array => is_array($value)
            ? array_values($value)
            : array_values(array_filter(preg_split('/[\s,]+/', (string) $value) ?: []));

        return new self(
            issuer: (string) $issuer,
            clientId: (string) ($options['client_id'] ?? ''),
            clientSecret: ($options['client_secret'] ?? null) ?: null,
            redirectUri: ($options['redirect_uri'] ?? null) ?: null,
            scopes: isset($options['scopes']) ? $list($options['scopes']) : ['openid', 'profile', 'email'],
            postLogoutRedirectUri: ($options['post_logout_redirect_uri'] ?? null) ?: null,
            audiences: isset($options['audiences']) ? $list($options['audiences']) : [],
            leeway: (int) ($options['leeway'] ?? 60),
            httpTimeout: (float) ($options['http_timeout'] ?? 10.0),
        );
    }

    public function isPublicClient(): bool
    {
        return $this->clientSecret === null;
    }

    public function realm(): ?Realm
    {
        return Realm::fromIssuer($this->issuer);
    }
}
