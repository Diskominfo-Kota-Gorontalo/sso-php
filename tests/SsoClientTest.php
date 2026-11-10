<?php

declare(strict_types=1);

namespace Gorontalokota\Sso\Tests;

use Gorontalokota\Sso\AuthorizationRequest;
use Gorontalokota\Sso\Cache\ArrayCache;
use Gorontalokota\Sso\Exception\AuthorizationDeniedException;
use Gorontalokota\Sso\Exception\InsufficientScopeException;
use Gorontalokota\Sso\Exception\InvalidStateException;
use Gorontalokota\Sso\Exception\SsoException;
use Gorontalokota\Sso\Exception\TokenValidationException;
use Gorontalokota\Sso\Internal\JwtVerifier;
use Gorontalokota\Sso\Realm;
use Gorontalokota\Sso\SsoClient;
use Gorontalokota\Sso\SsoConfig;
use Gorontalokota\Sso\Testing\FakeProvider;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

final class SsoClientTest extends TestCase
{
    private FakeProvider $provider;

    private ArrayCache $cache;

    protected function setUp(): void
    {
        $this->provider = new FakeProvider;
        $this->cache = new ArrayCache;
    }

    private function client(?string $secret = FakeProvider::SECRET, ?string $issuer = null): SsoClient
    {
        return new SsoClient(new SsoConfig(
            issuer: FakeProvider::ISSUER,
            clientId: FakeProvider::CLIENT_ID,
            clientSecret: $secret,
            redirectUri: 'https://app.test/sso/callback',
            postLogoutRedirectUri: 'https://app.test/',
        ), $this->provider->http($issuer), $this->cache);
    }

    /**
     * @return array{0: SsoClient, 1: AuthorizationRequest}
     */
    private function pendingLogin(?string $secret = FakeProvider::SECRET): array
    {
        $client = $this->client($secret);

        return [$client, $client->createAuthorizationRequest()];
    }

    private function respondWithTokens(string $nonce, array $idTokenOverrides = []): string
    {
        $accessToken = $this->provider->accessToken();
        $this->provider->tokenResponse = [
            'access_token' => $accessToken, 'token_type' => 'Bearer', 'expires_in' => 600, 'refresh_token' => 'refresh-1',
            'id_token' => $this->provider->idToken($nonce, ['at_hash' => JwtVerifier::hashClaim($accessToken), ...$idTokenOverrides]),
            'scope' => 'openid profile email',
        ];

        return $accessToken;
    }

    public function test_authorization_url_uses_pkce_s256_state_and_nonce(): void
    {
        $request = $this->client()->createAuthorizationRequest(['prompt' => 'login', 'state' => 'attacker'], '/dashboard');
        parse_str((string) parse_url($request->url, PHP_URL_QUERY), $query);

        self::assertStringStartsWith(FakeProvider::ISSUER.'/authorize?', $request->url);
        self::assertSame('code', $query['response_type']);
        self::assertSame('S256', $query['code_challenge_method']);
        self::assertSame(rtrim(strtr(base64_encode(hash('sha256', $request->codeVerifier, true)), '+/', '-_'), '='), $query['code_challenge']);
        self::assertSame($request->state, $query['state'], 'Callers cannot override protected parameters.');
        self::assertSame($request->nonce, $query['nonce']);
        self::assertSame('openid profile email', $query['scope']);
        self::assertSame('login', $query['prompt']);
        self::assertSame('/dashboard', $request->returnTo);
    }

    public function test_callback_exchanges_the_code_and_verifies_the_id_token(): void
    {
        [$client, $pending] = $this->pendingLogin();
        $accessToken = $this->respondWithTokens($pending->nonce);

        $tokens = $client->handleCallback(['code' => 'abc', 'state' => $pending->state], $pending);

        self::assertSame($accessToken, $tokens->accessToken);
        self::assertSame('refresh-1', $tokens->refreshToken);
        self::assertSame('sub-123', $tokens->user()?->sub);
        self::assertSame(Realm::Internal, $tokens->user()?->realm);
        self::assertSame('199001012020011001', $tokens->user()?->nip());

        $tokenRequest = $this->provider->requests[array_key_last($this->provider->requests) - 1];
        parse_str((string) $tokenRequest->getBody(), $form);
        self::assertSame($pending->codeVerifier, $form['code_verifier']);
        self::assertSame('Basic '.base64_encode(FakeProvider::CLIENT_ID.':'.FakeProvider::SECRET), $tokenRequest->getHeaderLine('Authorization'));
    }

    public function test_public_clients_send_their_client_id_instead_of_a_secret(): void
    {
        [$client, $pending] = $this->pendingLogin(null);
        $this->respondWithTokens($pending->nonce);

        $client->handleCallback(['code' => 'abc', 'state' => $pending->state], $pending);

        $tokenRequest = array_values(array_filter($this->provider->requests, fn ($r) => str_ends_with($r->getUri()->getPath(), '/token')))[0];
        parse_str((string) $tokenRequest->getBody(), $form);
        self::assertSame(FakeProvider::CLIENT_ID, $form['client_id']);
        self::assertSame('', $tokenRequest->getHeaderLine('Authorization'));
    }

    public function test_callback_rejects_a_wrong_or_missing_state(): void
    {
        [$client, $pending] = $this->pendingLogin();

        $this->expectException(InvalidStateException::class);
        $client->handleCallback(['code' => 'abc', 'state' => 'forged'], $pending);
    }

    public function test_callback_reports_a_denied_consent(): void
    {
        [$client, $pending] = $this->pendingLogin();

        try {
            $client->handleCallback(['error' => 'access_denied', 'error_description' => 'User menolak', 'state' => $pending->state], $pending);
            self::fail('Expected AuthorizationDeniedException.');
        } catch (AuthorizationDeniedException $exception) {
            self::assertSame('access_denied', $exception->error);
        }
    }

    /**
     * @return iterable<string, array{0: array<string, mixed>}>
     */
    public static function invalidIdTokens(): iterable
    {
        yield 'wrong nonce' => [['nonce' => 'replayed']];
        yield 'wrong audience' => [['aud' => 'other-client']];
        yield 'wrong issuer' => [['iss' => 'https://evil.test/internal']];
        yield 'expired' => [['exp' => time() - 3600, 'iat' => time() - 7200]];
        yield 'at_hash mismatch' => [['at_hash' => 'AAAAAAAAAAAAAAAAAAAAAA']];
    }

    /**
     * @param  array<string, mixed>  $overrides
     */
    #[DataProvider('invalidIdTokens')]
    public function test_invalid_id_tokens_are_rejected(array $overrides): void
    {
        [$client, $pending] = $this->pendingLogin();
        $this->respondWithTokens($pending->nonce, $overrides);

        $this->expectException(TokenValidationException::class);
        $client->handleCallback(['code' => 'abc', 'state' => $pending->state], $pending);
    }

    public function test_a_rotated_signing_key_is_picked_up_from_the_jwks(): void
    {
        $client = $this->client();
        $client->verifyAccessToken($this->provider->accessToken());
        self::assertSame(1, $this->provider->jwksFetches);

        $this->provider->addKey('key-2');
        $token = $this->provider->sign([
            'iss' => FakeProvider::ISSUER, 'aud' => FakeProvider::CLIENT_ID, 'sub' => 'sub-123', 'iat' => time(), 'exp' => time() + 600, 'scope' => 'openid',
        ], 'key-2', ['typ' => 'at+jwt']);

        $claims = (new SsoClient($client->config(), $this->provider->http(), $this->cache, fn () => time() + 120))->verifyAccessToken($token);

        self::assertSame('sub-123', $claims->subject);
        self::assertSame(2, $this->provider->jwksFetches);
    }

    public function test_a_token_signed_by_an_unpublished_key_is_rejected(): void
    {
        $this->provider->addKey('rogue', publish: false);
        $token = $this->provider->sign(['iss' => FakeProvider::ISSUER, 'aud' => FakeProvider::CLIENT_ID, 'sub' => 'x', 'exp' => time() + 60], 'rogue', ['typ' => 'at+jwt']);

        $this->expectException(TokenValidationException::class);
        $this->client()->verifyAccessToken($token);
    }

    public function test_bearer_access_tokens_are_verified_for_apis(): void
    {
        $claims = $this->client()->verifyAccessToken($this->provider->accessToken(), ['profile']);

        self::assertSame('sub-123', $claims->subject);
        self::assertSame(['openid', 'profile', 'email'], $claims->scopes);
        self::assertSame(Realm::Internal, $claims->realm);
    }

    /**
     * @return iterable<string, array{0: array<string, mixed>, 1: string}>
     */
    public static function invalidAccessTokens(): iterable
    {
        yield 'id token used as access token' => [[], 'JWT'];
        yield 'other audience' => [['aud' => 'another-app'], 'at+jwt'];
        yield 'expired' => [['exp' => time() - 3600, 'iat' => time() - 7200], 'at+jwt'];
    }

    /**
     * @param  array<string, mixed>  $overrides
     */
    #[DataProvider('invalidAccessTokens')]
    public function test_invalid_access_tokens_are_rejected(array $overrides, string $type): void
    {
        $this->expectException(TokenValidationException::class);
        $this->client()->verifyAccessToken($this->provider->accessToken($overrides, $type));
    }

    public function test_missing_scopes_are_reported(): void
    {
        try {
            $this->client()->verifyAccessToken($this->provider->accessToken(), ['employee']);
            self::fail('Expected InsufficientScopeException.');
        } catch (InsufficientScopeException $exception) {
            self::assertSame(['employee'], $exception->missingScopes);
        }
    }

    public function test_back_channel_logout_tokens_are_verified(): void
    {
        $token = $this->client()->verifyLogoutToken($this->provider->logoutToken());

        self::assertSame('sub-123', $token->subject);
        self::assertSame('sid-1', $token->sessionId);
    }

    /**
     * @return iterable<string, array{0: array<string, mixed>}>
     */
    public static function invalidLogoutTokens(): iterable
    {
        yield 'contains a nonce' => [['nonce' => 'n']];
        yield 'missing the logout event' => [['events' => ['other' => new \stdClass]]];
        yield 'neither sub nor sid' => [['sub' => null, 'sid' => null]];
        yield 'other audience' => [['aud' => 'another-app']];
    }

    public function test_an_access_token_cannot_be_used_as_a_logout_token(): void
    {
        $this->expectException(TokenValidationException::class);
        $this->client()->verifyLogoutToken($this->provider->accessToken());
    }

    /**
     * @param  array<string, mixed>  $overrides
     */
    #[DataProvider('invalidLogoutTokens')]
    public function test_invalid_logout_tokens_are_rejected(array $overrides): void
    {
        $claims = array_filter($overrides, fn ($value) => $value !== null);
        $token = $this->provider->logoutToken($claims);

        if (array_key_exists('sub', $overrides)) {
            $token = $this->provider->sign(['iss' => FakeProvider::ISSUER, 'aud' => FakeProvider::CLIENT_ID, 'iat' => time(), 'jti' => 'j', 'events' => ['http://schemas.openid.net/event/backchannel-logout' => new \stdClass]], 'key-1', ['typ' => 'logout+jwt']);
        }

        $this->expectException(TokenValidationException::class);
        $this->client()->verifyLogoutToken($token);
    }

    public function test_refresh_keeps_the_old_refresh_token_when_none_is_returned(): void
    {
        $this->provider->tokenResponse = ['access_token' => $this->provider->accessToken(), 'token_type' => 'Bearer', 'expires_in' => 600];

        $tokens = $this->client()->refresh('refresh-1');

        self::assertSame('refresh-1', $tokens->refreshToken);
    }

    public function test_logout_url_carries_the_id_token_hint_and_registered_redirect(): void
    {
        parse_str((string) parse_url($this->client()->logoutUrl('id.token.hint', 'xyz'), PHP_URL_QUERY), $query);

        self::assertSame('id.token.hint', $query['id_token_hint']);
        self::assertSame('https://app.test/', $query['post_logout_redirect_uri']);
        self::assertSame(FakeProvider::CLIENT_ID, $query['client_id']);
    }

    public function test_a_discovery_document_for_another_issuer_is_rejected(): void
    {
        $this->expectException(SsoException::class);
        $this->client(issuer: 'https://evil.test/internal')->createAuthorizationRequest();
    }

    /**
     * @return iterable<string, array{0: string|null, 1: string|null}>
     */
    public static function returnTargets(): iterable
    {
        yield 'local path' => ['/laporan?bulan=11', '/laporan?bulan=11'];
        yield 'absolute url' => ['https://evil.test/', null];
        yield 'protocol relative' => ['//evil.test/', null];
        yield 'backslash trick' => ['/\\evil.test', null];
        yield 'header injection' => ["/a\r\nLocation: x", null];
    }

    #[DataProvider('returnTargets')]
    public function test_return_to_only_accepts_local_paths(?string $input, ?string $expected): void
    {
        self::assertSame($expected, SsoClient::safeReturnTo($input));
    }

    public function test_config_can_be_built_from_a_realm(): void
    {
        $config = SsoConfig::fromArray(['realm' => 'external', 'client_id' => 'x', 'scopes' => 'profile phone']);

        self::assertSame('https://sso.gorontalokota.go.id/external', $config->issuer);
        self::assertSame(['openid', 'profile', 'phone'], $config->scopes);
        self::assertTrue($config->isPublicClient());
    }
}
