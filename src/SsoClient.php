<?php

declare(strict_types=1);

namespace Gorontalokota\Sso;

use Closure;
use Gorontalokota\Sso\Cache\ArrayCache;
use Gorontalokota\Sso\Exception\AuthorizationDeniedException;
use Gorontalokota\Sso\Exception\InsufficientScopeException;
use Gorontalokota\Sso\Exception\InvalidStateException;
use Gorontalokota\Sso\Exception\SsoException;
use Gorontalokota\Sso\Exception\TokenValidationException;
use Gorontalokota\Sso\Internal\HttpTransport;
use Gorontalokota\Sso\Internal\JwtVerifier;
use GuzzleHttp\Client;
use GuzzleHttp\ClientInterface;
use Psr\SimpleCache\CacheInterface;

/**
 * OpenID Connect client for the Pemerintah Kota Gorontalo SSO.
 *
 * Flow: createAuthorizationRequest() → store it in the session → redirect to $request->url → on the callback call
 * handleCallback($_GET, $storedRequest) → link the local account by $tokens->user()->sub.
 */
final class SsoClient
{
    private const METADATA_TTL = 3600;

    private const BACKCHANNEL_EVENT = 'http://schemas.openid.net/event/backchannel-logout';

    private readonly HttpTransport $http;

    private readonly CacheInterface $cache;

    private readonly JwtVerifier $jwt;

    /** @var Closure(): int */
    private readonly Closure $now;

    /** @var array<string, mixed>|null */
    private ?array $metadata = null;

    /**
     * @param  CacheInterface|null  $cache  Caches discovery metadata and JWKS. Pass the app cache to avoid refetching on every request.
     * @param  (Closure(): int)|null  $now  Clock override for tests.
     */
    public function __construct(
        private readonly SsoConfig $config,
        ?ClientInterface $http = null,
        ?CacheInterface $cache = null,
        ?Closure $now = null,
    ) {
        $this->now = $now ?? static fn (): int => time();
        $this->cache = $cache ?? new ArrayCache;
        $this->http = new HttpTransport($http ?? new Client, $config->httpTimeout);
        $this->jwt = new JwtVerifier(
            $this->http,
            $this->cache,
            fn (): string => $this->endpoint('jwks_uri'),
            $this->now,
            $config->leeway,
        );
    }

    public function config(): SsoConfig
    {
        return $this->config;
    }

    /**
     * Discovery document of the realm ({issuer}/.well-known/openid-configuration).
     *
     * @return array<string, mixed>
     */
    public function metadata(): array
    {
        if ($this->metadata !== null) {
            return $this->metadata;
        }

        $cacheKey = 'gorontalokota_sso.metadata.'.sha1($this->config->issuer);
        $metadata = $this->cache->get($cacheKey);

        if (! is_array($metadata)) {
            $metadata = $this->http->getJson(rtrim($this->config->issuer, '/').'/.well-known/openid-configuration');

            if (($metadata['issuer'] ?? null) !== $this->config->issuer) {
                throw new SsoException('Discovery issuer does not match the configured issuer '.$this->config->issuer.'.');
            }

            $this->cache->set($cacheKey, $metadata, self::METADATA_TTL);
        }

        return $this->metadata = $metadata;
    }

    /**
     * Builds the login redirect with PKCE (S256), state and nonce.
     *
     * @param  array<string, string>  $parameters  Extra authorization parameters, e.g. ['prompt' => 'login'] or ['login_hint' => '...'].
     * @param  string|null  $returnTo  Local path to return to after login (kept in the pending request).
     */
    public function createAuthorizationRequest(array $parameters = [], ?string $returnTo = null): AuthorizationRequest
    {
        if ($this->config->redirectUri === null) {
            throw new SsoException('redirect_uri must be configured to start a login.');
        }

        $state = self::random();
        $nonce = self::random();
        $verifier = self::random(48);

        $protected = [
            'response_type' => 'code',
            'client_id' => $this->config->clientId,
            'redirect_uri' => $this->config->redirectUri,
            'scope' => implode(' ', $this->config->scopes),
            'state' => $state,
            'nonce' => $nonce,
            'code_challenge' => self::base64Url(hash('sha256', $verifier, true)),
            'code_challenge_method' => 'S256',
        ];

        $endpoint = $this->endpoint('authorization_endpoint');
        $query = http_build_query([...array_diff_key($parameters, $protected), ...$protected], '', '&', PHP_QUERY_RFC3986);

        return new AuthorizationRequest(
            url: $endpoint.(str_contains($endpoint, '?') ? '&' : '?').$query,
            state: $state,
            nonce: $nonce,
            codeVerifier: $verifier,
            createdAt: ($this->now)(),
            returnTo: self::safeReturnTo($returnTo),
        );
    }

    /**
     * Completes the login on the redirect URI: checks state, exchanges the code and verifies the ID token.
     *
     * @param  array<string, mixed>  $query  The callback query string, usually $_GET.
     * @param  int  $maxAge  Seconds a pending login stays valid.
     *
     * @throws AuthorizationDeniedException when the user refused or the SSO returned an error
     * @throws InvalidStateException when state is missing, wrong, or expired
     */
    public function handleCallback(array $query, AuthorizationRequest $pending, int $maxAge = 900): TokenSet
    {
        if (isset($query['error'])) {
            throw new AuthorizationDeniedException((string) $query['error'], isset($query['error_description']) ? (string) $query['error_description'] : null);
        }

        $state = isset($query['state']) ? (string) $query['state'] : '';

        if ($pending->state === '' || ! hash_equals($pending->state, $state)) {
            throw new InvalidStateException('Login state does not match. Start the login again.');
        }

        if (($this->now)() - $pending->createdAt > $maxAge) {
            throw new InvalidStateException('Login request expired. Start the login again.');
        }

        $code = isset($query['code']) ? (string) $query['code'] : '';

        if ($code === '') {
            throw new InvalidStateException('Callback is missing the authorization code.');
        }

        $response = $this->tokenRequest([
            'grant_type' => 'authorization_code',
            'code' => $code,
            'redirect_uri' => (string) $this->config->redirectUri,
            'code_verifier' => $pending->codeVerifier,
        ]);

        if (! isset($response['id_token'])) {
            throw new TokenValidationException('Token response has no id_token; request the "openid" scope.');
        }

        return $this->tokenSet($response, $pending->nonce);
    }

    /**
     * Gets a fresh access token. Refresh tokens rotate: always store the returned refresh token.
     */
    public function refresh(string $refreshToken): TokenSet
    {
        $response = $this->tokenRequest(['grant_type' => 'refresh_token', 'refresh_token' => $refreshToken]);
        $response['refresh_token'] ??= $refreshToken;

        return $this->tokenSet($response, null);
    }

    /**
     * Latest claims from the userinfo endpoint.
     *
     * @return array<string, mixed>
     */
    public function userinfo(string $accessToken): array
    {
        $claims = $this->http->getJson($this->endpoint('userinfo_endpoint'), ['Authorization' => 'Bearer '.$accessToken]);

        if (! isset($claims['sub'])) {
            throw new TokenValidationException('Userinfo response has no "sub".');
        }

        return $claims;
    }

    /**
     * RP-initiated logout URL. Clear the local session first, then redirect the browser here.
     */
    public function logoutUrl(?string $idTokenHint = null, ?string $state = null, ?string $postLogoutRedirectUri = null): string
    {
        $endpoint = $this->endpoint('end_session_endpoint');
        $query = array_filter([
            'client_id' => $this->config->clientId,
            'id_token_hint' => $idTokenHint,
            'post_logout_redirect_uri' => $postLogoutRedirectUri ?? $this->config->postLogoutRedirectUri,
            'state' => $state,
        ], fn (?string $value): bool => $value !== null && $value !== '');

        return $endpoint.(str_contains($endpoint, '?') ? '&' : '?').http_build_query($query, '', '&', PHP_QUERY_RFC3986);
    }

    public function revoke(string $token, string $tokenTypeHint = 'refresh_token'): void
    {
        $this->http->postForm(
            $this->endpoint('revocation_endpoint'),
            [...$this->clientAuthForm(), 'token' => $token, 'token_type_hint' => $tokenTypeHint],
            $this->clientAuthHeaders(),
            expectJson: false,
        );
    }

    /**
     * Asks the SSO whether a token is still active (catches revocation before expiry). Confidential clients only.
     *
     * @return array<string, mixed>
     */
    public function introspect(string $token): array
    {
        if ($this->config->isPublicClient()) {
            throw new SsoException('Token introspection requires a client secret.');
        }

        return $this->http->postForm($this->endpoint('introspection_endpoint'), ['token' => $token], $this->clientAuthHeaders());
    }

    /**
     * Verifies a bearer access token locally (signature via JWKS, issuer, audience, expiry, type) for APIs.
     *
     * @param  list<string>  $requiredScopes
     *
     * @throws TokenValidationException
     * @throws InsufficientScopeException
     */
    public function verifyAccessToken(string $jwt, array $requiredScopes = []): AccessTokenClaims
    {
        [$claims, $header] = $this->jwt->verify($jwt);

        $type = strtolower((string) ($header['typ'] ?? ''));

        if ($type !== 'at+jwt' && $type !== 'application/at+jwt') {
            throw new TokenValidationException('Token is not an access token (typ must be at+jwt).');
        }

        $this->assertIssuer($claims);

        if (array_intersect($this->audiences($claims), $this->config->audiences) === []) {
            throw new TokenValidationException('Access token audience is not accepted by this API.');
        }

        if (! isset($claims['sub'], $claims['exp'])) {
            throw new TokenValidationException('Access token is missing "sub" or "exp".');
        }

        $scopes = array_values(array_filter(explode(' ', (string) ($claims['scope'] ?? ''))));
        $missing = array_values(array_diff($requiredScopes, $scopes));

        if ($missing !== []) {
            throw new InsufficientScopeException($missing);
        }

        return new AccessTokenClaims(
            subject: (string) $claims['sub'],
            clientId: (string) ($claims['client_id'] ?? ($this->audiences($claims)[0] ?? '')),
            scopes: $scopes,
            realm: Realm::fromIssuer((string) $claims['iss']),
            sessionId: isset($claims['sid']) ? (string) $claims['sid'] : null,
            expiresAt: (int) $claims['exp'],
            claims: $claims,
        );
    }

    /**
     * Verifies a back-channel logout token (OpenID Connect Back-Channel Logout 1.0, section 2.6).
     *
     * @throws TokenValidationException
     */
    public function verifyLogoutToken(string $jwt): LogoutToken
    {
        [$claims, $header] = $this->jwt->verify($jwt);

        // Explicit typing stops an ID or access token from being replayed as a logout token.
        if (strtolower((string) ($header['typ'] ?? '')) !== 'logout+jwt') {
            throw new TokenValidationException('Token is not a logout token (typ must be logout+jwt).');
        }

        $this->assertIssuer($claims);

        if (! in_array($this->config->clientId, $this->audiences($claims), true)) {
            throw new TokenValidationException('Logout token audience does not match this client.');
        }

        if (! isset($claims['iat'], $claims['jti'])) {
            throw new TokenValidationException('Logout token is missing "iat" or "jti".');
        }

        if (! isset($claims['events']) || ! is_array($claims['events']) || ! array_key_exists(self::BACKCHANNEL_EVENT, $claims['events'])) {
            throw new TokenValidationException('Logout token is missing the back-channel logout event.');
        }

        if (array_key_exists('nonce', $claims)) {
            throw new TokenValidationException('Logout token must not contain a nonce.');
        }

        if (! isset($claims['sub']) && ! isset($claims['sid'])) {
            throw new TokenValidationException('Logout token must contain "sub" or "sid".');
        }

        return new LogoutToken(
            subject: isset($claims['sub']) ? (string) $claims['sub'] : null,
            sessionId: isset($claims['sid']) ? (string) $claims['sid'] : null,
            issuedAt: (int) $claims['iat'],
            id: (string) $claims['jti'],
            claims: $claims,
        );
    }

    /**
     * Accepts only local paths ("/dashboard?x=1"), never absolute or protocol-relative URLs (open redirect).
     */
    public static function safeReturnTo(?string $returnTo): ?string
    {
        if ($returnTo === null || $returnTo === '' || ! str_starts_with($returnTo, '/') || str_starts_with($returnTo, '//') || str_contains($returnTo, '\\')) {
            return null;
        }

        return preg_match('/[\x00-\x1F\x7F]/', $returnTo) === 1 ? null : $returnTo;
    }

    /**
     * @param  array<string, string>  $form
     * @return array<string, mixed>
     */
    private function tokenRequest(array $form): array
    {
        $response = $this->http->postForm($this->endpoint('token_endpoint'), [...$this->clientAuthForm(), ...$form], $this->clientAuthHeaders());

        if (! isset($response['access_token']) || strtolower((string) ($response['token_type'] ?? '')) !== 'bearer') {
            throw new TokenValidationException('Token response is missing a bearer access_token.');
        }

        return $response;
    }

    /**
     * @param  array<string, mixed>  $response
     */
    private function tokenSet(array $response, ?string $expectedNonce): TokenSet
    {
        $accessToken = (string) $response['access_token'];
        $idToken = isset($response['id_token']) ? (string) $response['id_token'] : null;

        return new TokenSet(
            accessToken: $accessToken,
            expiresAt: ($this->now)() + (int) ($response['expires_in'] ?? 300),
            refreshToken: isset($response['refresh_token']) ? (string) $response['refresh_token'] : null,
            idToken: $idToken,
            idTokenClaims: $idToken !== null ? $this->verifyIdToken($idToken, $expectedNonce, $accessToken) : [],
            scope: (string) ($response['scope'] ?? implode(' ', $this->config->scopes)),
        );
    }

    /**
     * @return array<string, mixed>
     */
    private function verifyIdToken(string $idToken, ?string $expectedNonce, string $accessToken): array
    {
        [$claims] = $this->jwt->verify($idToken);

        $this->assertIssuer($claims);
        $audiences = $this->audiences($claims);

        if (! in_array($this->config->clientId, $audiences, true)) {
            throw new TokenValidationException('ID token audience does not match this client.');
        }

        if (count($audiences) > 1 && ($claims['azp'] ?? null) !== $this->config->clientId) {
            throw new TokenValidationException('ID token azp does not match this client.');
        }

        if (! isset($claims['sub'], $claims['exp'], $claims['iat'])) {
            throw new TokenValidationException('ID token is missing "sub", "exp" or "iat".');
        }

        if ($expectedNonce !== null && ! hash_equals($expectedNonce, (string) ($claims['nonce'] ?? ''))) {
            throw new TokenValidationException('ID token nonce does not match the login request.');
        }

        if (isset($claims['at_hash']) && ! hash_equals(JwtVerifier::hashClaim($accessToken), (string) $claims['at_hash'])) {
            throw new TokenValidationException('ID token at_hash does not match the access token.');
        }

        return $claims;
    }

    /**
     * @param  array<string, mixed>  $claims
     */
    private function assertIssuer(array $claims): void
    {
        if (($claims['iss'] ?? null) !== $this->config->issuer) {
            throw new TokenValidationException('Token issuer does not match '.$this->config->issuer.'.');
        }
    }

    /**
     * @param  array<string, mixed>  $claims
     * @return list<string>
     */
    private function audiences(array $claims): array
    {
        $aud = $claims['aud'] ?? [];

        return array_values(array_map('strval', is_array($aud) ? $aud : [$aud]));
    }

    private function endpoint(string $name): string
    {
        $url = $this->metadata()[$name] ?? null;

        if (! is_string($url) || $url === '') {
            throw new SsoException("SSO discovery document has no {$name}.");
        }

        return $url;
    }

    /**
     * @return array<string, string>
     */
    private function clientAuthHeaders(): array
    {
        if ($this->config->clientSecret === null) {
            return [];
        }

        // The SSO reads Basic credentials verbatim (no form-urldecoding), so they are sent unencoded.
        return ['Authorization' => 'Basic '.base64_encode($this->config->clientId.':'.$this->config->clientSecret)];
    }

    /**
     * @return array<string, string>
     */
    private function clientAuthForm(): array
    {
        return $this->config->clientSecret === null ? ['client_id' => $this->config->clientId] : [];
    }

    /**
     * @param  positive-int  $bytes
     */
    private static function random(int $bytes = 32): string
    {
        return self::base64Url(random_bytes($bytes));
    }

    private static function base64Url(string $value): string
    {
        return rtrim(strtr(base64_encode($value), '+/', '-_'), '=');
    }
}
