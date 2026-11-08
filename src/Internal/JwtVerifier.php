<?php

declare(strict_types=1);

namespace Gorontalokota\Sso\Internal;

use Closure;
use Firebase\JWT\JWK;
use Firebase\JWT\JWT;
use Gorontalokota\Sso\Exception\HttpException;
use Gorontalokota\Sso\Exception\TokenValidationException;
use Psr\SimpleCache\CacheInterface;
use Throwable;

/**
 * @internal Verifies RS256 JWTs against the realm JWKS. Caches the key set and refetches it once when a token
 * carries an unknown "kid" (signing key rotation), at most once per minute.
 */
final class JwtVerifier
{
    private const JWKS_TTL = 3600;

    private const REFETCH_INTERVAL = 10;

    /**
     * @param  Closure(): string  $jwksUri
     * @param  Closure(): int  $now
     */
    public function __construct(
        private readonly HttpTransport $http,
        private readonly CacheInterface $cache,
        private readonly Closure $jwksUri,
        private readonly Closure $now,
        private readonly int $leeway,
    ) {}

    /**
     * Verifies signature, alg (RS256 only), exp, nbf and iat. Claim semantics (iss, aud, ...) are checked by the caller.
     *
     * @return array{0: array<string, mixed>, 1: array<string, mixed>} [claims, header]
     */
    public function verify(string $jwt): array
    {
        $header = $this->header($jwt);

        if (($header['alg'] ?? null) !== 'RS256') {
            throw new TokenValidationException('Token must be signed with RS256.');
        }

        $kid = isset($header['kid']) ? (string) $header['kid'] : null;
        $keys = $this->keys(false);

        if ($kid === null || ! isset($keys[$kid])) {
            $keys = $this->keys(true);
        }

        if ($kid === null || ! isset($keys[$kid])) {
            throw new TokenValidationException('Token signing key (kid) is not published by the SSO.');
        }

        $previousLeeway = JWT::$leeway;
        $previousTimestamp = JWT::$timestamp;
        JWT::$leeway = $this->leeway;
        JWT::$timestamp = ($this->now)();

        try {
            $claims = JWT::decode($jwt, $keys);
        } catch (Throwable $exception) {
            throw new TokenValidationException('Token verification failed: '.$exception->getMessage(), 0, $exception);
        } finally {
            JWT::$leeway = $previousLeeway;
            JWT::$timestamp = $previousTimestamp;
        }

        /** @var array<string, mixed> $array */
        $array = json_decode((string) json_encode($claims), true);

        return [$array, $header];
    }

    /**
     * @return array<string, mixed>
     */
    private function header(string $jwt): array
    {
        $parts = explode('.', $jwt);

        if (count($parts) !== 3) {
            throw new TokenValidationException('Token is not a JWS compact serialization.');
        }

        $header = json_decode(JWT::urlsafeB64Decode($parts[0]), true);

        if (! is_array($header)) {
            throw new TokenValidationException('Token header is not valid JSON.');
        }

        return $header;
    }

    /**
     * @return array<string, \Firebase\JWT\Key>
     */
    private function keys(bool $refresh): array
    {
        $uri = ($this->jwksUri)();
        $cacheKey = 'gorontalokota_sso.jwks.'.sha1($uri);
        $cached = $this->cache->get($cacheKey);
        $now = ($this->now)();

        if (is_array($cached) && (! $refresh || $now - (int) ($cached['fetched_at'] ?? 0) < self::REFETCH_INTERVAL)) {
            return $this->parse($cached['jwks'] ?? []);
        }

        try {
            $jwks = $this->http->getJson($uri);
        } catch (HttpException $exception) {
            if (is_array($cached)) {
                return $this->parse($cached['jwks'] ?? []);
            }

            throw $exception;
        }

        $this->cache->set($cacheKey, ['jwks' => $jwks, 'fetched_at' => $now], self::JWKS_TTL);

        return $this->parse($jwks);
    }

    /**
     * @param  mixed  $jwks
     * @return array<string, \Firebase\JWT\Key>
     */
    private function parse(mixed $jwks): array
    {
        if (! is_array($jwks) || ! isset($jwks['keys']) || ! is_array($jwks['keys'])) {
            throw new TokenValidationException('SSO JWKS is malformed.');
        }

        $rsaKeys = array_values(array_filter($jwks['keys'], fn (mixed $key): bool => is_array($key) && ($key['kty'] ?? null) === 'RSA' && isset($key['kid'])));

        return $rsaKeys === [] ? [] : JWK::parseKeySet(['keys' => $rsaKeys], 'RS256');
    }

    public static function hashClaim(string $value): string
    {
        $hash = hash('sha256', $value, true);

        return rtrim(strtr(base64_encode(substr($hash, 0, intdiv(strlen($hash), 2))), '+/', '-_'), '=');
    }
}
