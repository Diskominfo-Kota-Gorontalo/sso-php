<?php

declare(strict_types=1);

namespace Gorontalokota\Sso\Testing;

use Firebase\JWT\JWT;
use GuzzleHttp\Client;
use GuzzleHttp\HandlerStack;
use GuzzleHttp\Psr7\Response;
use Psr\Http\Message\RequestInterface;

/**
 * In-memory fake of the SSO for tests: serves discovery, JWKS, token and userinfo through a Guzzle handler
 * and signs ID, access and logout tokens exactly like the real server. Pass $provider->http() to SsoClient.
 */
final class FakeProvider
{
    public const ISSUER = 'https://sso.test/internal';

    public const CLIENT_ID = 'internal-retribusi';

    public const SECRET = 'rahasia';

    public readonly string $issuer;

    public readonly string $clientId;

    /** @var array<string, array{private: string, jwk: array<string, string>}> */
    private array $keys = [];

    /** @var list<string> Key ids currently published in the JWKS. */
    public array $published = [];

    /** @var list<RequestInterface> */
    public array $requests = [];

    /** @var array<string, mixed>|null Next token endpoint response body. */
    public ?array $tokenResponse = null;

    public int $jwksFetches = 0;

    public function __construct(?string $issuer = null, ?string $clientId = null)
    {
        $this->issuer = $issuer ?? self::ISSUER;
        $this->clientId = $clientId ?? self::CLIENT_ID;
        $this->addKey('key-1');
    }

    public function addKey(string $kid, bool $publish = true): void
    {
        $resource = openssl_pkey_new(['private_key_bits' => 2048, 'private_key_type' => OPENSSL_KEYTYPE_RSA]);
        $details = $resource !== false ? openssl_pkey_get_details($resource) : false;

        if ($resource === false || $details === false || ! openssl_pkey_export($resource, $private)) {
            throw new \RuntimeException('OpenSSL could not generate an RSA test key.');
        }

        $b64 = static fn (string $v): string => rtrim(strtr(base64_encode($v), '+/', '-_'), '=');

        $this->keys[$kid] = [
            'private' => $private,
            'jwk' => ['kty' => 'RSA', 'kid' => $kid, 'use' => 'sig', 'alg' => 'RS256', 'n' => $b64($details['rsa']['n']), 'e' => $b64($details['rsa']['e'])],
        ];

        if ($publish) {
            $this->published[] = $kid;
        }
    }

    /**
     * @param  array<string, mixed>  $claims
     * @param  array<string, string>  $headers
     */
    public function sign(array $claims, string $kid = 'key-1', array $headers = []): string
    {
        return JWT::encode($claims, $this->keys[$kid]['private'], 'RS256', $kid, $headers);
    }

    /**
     * @param  array<string, mixed>  $overrides
     */
    public function idToken(string $nonce, array $overrides = [], string $kid = 'key-1'): string
    {
        return $this->sign([
            'iss' => $this->issuer, 'aud' => $this->clientId, 'sub' => 'sub-123', 'iat' => time(), 'exp' => time() + 600,
            'auth_time' => time(), 'nonce' => $nonce, 'sid' => 'sid-1', 'name' => 'Budi Santoso', 'preferred_username' => '199001012020011001',
            ...$overrides,
        ], $kid);
    }

    /**
     * @param  array<string, mixed>  $overrides
     */
    public function accessToken(array $overrides = [], string $type = 'at+jwt'): string
    {
        return $this->sign([
            'iss' => $this->issuer, 'aud' => $this->clientId, 'sub' => 'sub-123', 'iat' => time(), 'exp' => time() + 600, 'jti' => 'jti-1',
            'client_id' => $this->clientId, 'scope' => 'openid profile email', 'realm' => 'internal', 'sid' => 'sid-1',
            ...$overrides,
        ], 'key-1', ['typ' => $type]);
    }

    /**
     * @param  array<string, mixed>  $overrides
     */
    public function logoutToken(array $overrides = []): string
    {
        return $this->sign([
            'iss' => $this->issuer, 'aud' => $this->clientId, 'iat' => time(), 'jti' => 'logout-1', 'sub' => 'sub-123', 'sid' => 'sid-1',
            'events' => ['http://schemas.openid.net/event/backchannel-logout' => new \stdClass],
            ...$overrides,
        ], 'key-1', ['typ' => 'logout+jwt']);
    }

    /**
     * @param  string|null  $discoveryIssuer  Issuer announced by discovery (override to simulate a mismatch).
     */
    public function http(?string $discoveryIssuer = null): Client
    {
        $stack = HandlerStack::create(function (RequestInterface $request, array $options) use ($discoveryIssuer) {
            $this->requests[] = $request;

            return \GuzzleHttp\Promise\Create::promiseFor($this->respond($request, $discoveryIssuer ?? $this->issuer));
        });

        return new Client(['handler' => $stack]);
    }

    private function respond(RequestInterface $request, string $issuer): Response
    {
        $path = $request->getUri()->getPath();

        return match (true) {
            str_ends_with($path, '/.well-known/openid-configuration') => $this->json([
                'issuer' => $issuer,
                'authorization_endpoint' => $this->issuer.'/authorize',
                'token_endpoint' => $this->issuer.'/token',
                'userinfo_endpoint' => $this->issuer.'/userinfo',
                'jwks_uri' => $this->issuer.'/jwks',
                'revocation_endpoint' => $this->issuer.'/revoke',
                'introspection_endpoint' => $this->issuer.'/introspect',
                'end_session_endpoint' => $this->issuer.'/logout',
            ]),
            str_ends_with($path, '/jwks') => $this->jwks(),
            str_ends_with($path, '/token') => $this->json($this->tokenResponse ?? ['error' => 'invalid_grant'], $this->tokenResponse === null ? 400 : 200),
            str_ends_with($path, '/userinfo') => $this->json(['sub' => 'sub-123', 'name' => 'Budi Santoso']),
            str_ends_with($path, '/revoke') => new Response(200),
            default => new Response(404),
        };
    }

    private function jwks(): Response
    {
        $this->jwksFetches++;

        return $this->json(['keys' => array_map(fn (string $kid): array => $this->keys[$kid]['jwk'], $this->published)]);
    }

    /**
     * @param  array<string, mixed>  $body
     */
    private function json(array $body, int $status = 200): Response
    {
        return new Response($status, ['Content-Type' => 'application/json'], (string) json_encode($body));
    }
}
