<?php

declare(strict_types=1);

namespace Gorontalokota\Sso\Logout;

use Gorontalokota\Sso\LogoutToken;
use Psr\SimpleCache\CacheInterface;

/**
 * Remembers sessions ended by back-channel logout so every app instance can sign the user out on the next request.
 *
 * Framework-agnostic: the back-channel request has no browser session, so instead of deleting the session there,
 * the app records "this SSO session ended" in a shared cache and checks it on each authenticated request.
 */
final class LogoutRegistry
{
    private const PREFIX = 'gorontalokota_sso.logout.';

    /**
     * @param  CacheInterface  $cache  Must be shared between requests and servers (Redis, database, FileCache on one server).
     * @param  int  $ttl  Seconds to remember an ended session; must exceed the longest SSO session (30 days for the external realm).
     */
    public function __construct(
        private readonly CacheInterface $cache,
        private readonly int $ttl = 31 * 24 * 3600,
    ) {}

    public function markEnded(LogoutToken $token): void
    {
        if ($token->sessionId !== null) {
            $this->cache->set($this->key('sid', $token->sessionId), true, $this->ttl);

            return;
        }

        if ($token->subject !== null) {
            $key = $this->key('sub', $token->subject);
            $previous = (int) $this->cache->get($key, 0);
            $this->cache->set($key, max($previous, $token->issuedAt), $this->ttl);
        }
    }

    /**
     * @param  int  $authenticatedAt  Unix time the local session was created from the SSO login.
     */
    public function isEnded(string $subject, ?string $sessionId, int $authenticatedAt): bool
    {
        if ($sessionId !== null && $this->cache->get($this->key('sid', $sessionId), false) === true) {
            return true;
        }

        $endedAt = (int) $this->cache->get($this->key('sub', $subject), 0);

        return $endedAt > 0 && $authenticatedAt <= $endedAt;
    }

    private function key(string $type, string $value): string
    {
        return self::PREFIX.$type.'.'.hash('sha256', $value);
    }
}
