<?php

declare(strict_types=1);

namespace Gorontalokota\Sso\Native;

use Gorontalokota\Sso\AuthorizationRequest;
use Gorontalokota\Sso\Exception\SsoException;
use Gorontalokota\Sso\Exception\TokenValidationException;
use Gorontalokota\Sso\Logout\LogoutRegistry;
use Gorontalokota\Sso\SsoClient;
use Gorontalokota\Sso\SsoUser;
use Gorontalokota\Sso\TokenSet;

/**
 * Ready-made login session on top of PHP's native $_SESSION, for PHP native and CodeIgniter 3 apps.
 *
 *   login.php:        $auth->redirectToLogin($_GET['return_to'] ?? null);
 *   callback.php:     $user = $auth->handleCallback($_GET); header('Location: '.$auth->pullReturnTo('/'));
 *   any page:         $user = $auth->user() ?? $auth->redirectToLogin($_SERVER['REQUEST_URI']);
 *   logout.php (POST): header('Location: '.$auth->logout());
 *   backchannel.php:  http_response_code($auth->handleBackchannelLogout($_POST['logout_token'] ?? null));
 */
final class SsoAuth
{
    /**
     * @param  LogoutRegistry|null  $registry  Enables back-channel logout (shared cache, e.g. FileCache or Redis).
     * @param  string  $sessionKey  Key under $_SESSION used by this SDK.
     */
    public function __construct(
        private readonly SsoClient $client,
        private readonly ?LogoutRegistry $registry = null,
        private readonly string $sessionKey = 'gorontalokota_sso',
    ) {}

    public function client(): SsoClient
    {
        return $this->client;
    }

    /**
     * Stores a pending login in the session and returns the SSO URL to redirect to.
     *
     * @param  array<string, string>  $parameters
     */
    public function loginUrl(?string $returnTo = null, array $parameters = []): string
    {
        $request = $this->client->createAuthorizationRequest($parameters, $returnTo);
        $this->session()['pending'] = $request->toArray();

        return $request->url;
    }

    /**
     * @param  array<string, string>  $parameters
     */
    public function redirectToLogin(?string $returnTo = null, array $parameters = []): never
    {
        self::redirect($this->loginUrl($returnTo, $parameters));
    }

    /**
     * Completes the login and starts the local session. Session id is regenerated to prevent fixation.
     *
     * @param  array<string, mixed>  $query  Usually $_GET.
     */
    public function handleCallback(array $query): SsoUser
    {
        $session = &$this->session();
        $pending = $session['pending'] ?? null;
        unset($session['pending']);

        if (! is_array($pending)) {
            throw new SsoException('No pending SSO login in this session. Start the login again.');
        }

        $request = AuthorizationRequest::fromArray($pending);
        $tokens = $this->client->handleCallback($query, $request);
        $user = $tokens->user() ?? throw new TokenValidationException('Login returned no ID token.');

        session_regenerate_id(true);
        $session = &$this->session();
        $session['tokens'] = $tokens->toArray();
        $session['authenticated_at'] = time();
        $session['return_to'] = $request->returnTo;

        return $user;
    }

    /**
     * Local path saved by loginUrl($returnTo), consumed once.
     */
    public function pullReturnTo(string $default = '/'): string
    {
        $session = &$this->session();
        $returnTo = SsoClient::safeReturnTo($session['return_to'] ?? null);
        unset($session['return_to']);

        return $returnTo ?? $default;
    }

    /**
     * The signed-in user, or null. Returns null (and clears the session) when the SSO session ended via back-channel logout.
     */
    public function user(): ?SsoUser
    {
        $tokens = $this->tokens();

        if ($tokens === null) {
            return null;
        }

        $user = $tokens->user();

        if ($user === null) {
            return null;
        }

        if ($this->registry !== null && $this->registry->isEnded($user->sub, $user->sessionId, (int) ($this->session()['authenticated_at'] ?? 0))) {
            $this->clear();

            return null;
        }

        return $user;
    }

    /**
     * Access token for calling SSO-protected APIs, refreshed automatically when about to expire.
     * Returns null when the user is not signed in or the refresh failed (session ended at the SSO).
     */
    public function accessToken(): ?string
    {
        $tokens = $this->tokens();

        if ($tokens === null || $this->user() === null) {
            return null;
        }

        if (! $tokens->isExpired(time())) {
            return $tokens->accessToken;
        }

        if ($tokens->refreshToken === null) {
            return null;
        }

        try {
            $fresh = $this->client->refresh($tokens->refreshToken);
        } catch (SsoException) {
            $this->clear();

            return null;
        }

        $this->session()['tokens'] = (new TokenSet(
            accessToken: $fresh->accessToken,
            expiresAt: $fresh->expiresAt,
            refreshToken: $fresh->refreshToken,
            idToken: $fresh->idToken ?? $tokens->idToken,
            idTokenClaims: $fresh->idTokenClaims !== [] ? $fresh->idTokenClaims : $tokens->idTokenClaims,
            scope: $fresh->scope,
        ))->toArray();

        return $fresh->accessToken;
    }

    /**
     * Ends the local session and returns the SSO end-session URL to redirect to (signs out of the SSO as well).
     * Call from a POST handler with CSRF protection.
     */
    public function logout(?string $postLogoutRedirectUri = null): string
    {
        $idToken = $this->tokens()?->idToken;
        $this->clear();
        session_regenerate_id(true);

        return $this->client->logoutUrl($idToken, null, $postLogoutRedirectUri);
    }

    /**
     * Handles POST {backchannel_logout_uri}. Returns the HTTP status to send (200 or 400) and sets no-store headers.
     */
    public function handleBackchannelLogout(?string $logoutToken): int
    {
        if (! headers_sent()) {
            header('Cache-Control: no-store');
        }

        if ($this->registry === null || $logoutToken === null || $logoutToken === '') {
            return 400;
        }

        try {
            $this->registry->markEnded($this->client->verifyLogoutToken($logoutToken));
        } catch (SsoException) {
            return 400;
        }

        return 200;
    }

    private function tokens(): ?TokenSet
    {
        $data = $this->session()['tokens'] ?? null;

        return is_array($data) ? TokenSet::fromArray($data) : null;
    }

    private function clear(): void
    {
        $session = &$this->session();
        $session = [];
    }

    /**
     * @return array<string, mixed>
     */
    private function &session(): array
    {
        if (session_status() !== PHP_SESSION_ACTIVE) {
            if (headers_sent()) {
                throw new SsoException('Start the PHP session (session_start()) before sending output.');
            }

            session_start(['cookie_httponly' => true, 'cookie_samesite' => 'Lax', 'use_strict_mode' => true]);
        }

        if (! isset($_SESSION[$this->sessionKey]) || ! is_array($_SESSION[$this->sessionKey])) {
            $_SESSION[$this->sessionKey] = [];
        }

        return $_SESSION[$this->sessionKey];
    }

    private static function redirect(string $url): never
    {
        header('Location: '.$url, true, 302);
        exit;
    }
}
