<?php

declare(strict_types=1);

namespace Gorontalokota\Sso;

/**
 * A verified back-channel logout token. When $sessionId is null every session of $subject issued at or before
 * $issuedAt has ended (e.g. the account was deactivated or signed out of all devices by an admin).
 */
final class LogoutToken
{
    /**
     * @param  array<string, mixed>  $claims
     */
    public function __construct(
        public readonly ?string $subject,
        public readonly ?string $sessionId,
        public readonly int $issuedAt,
        public readonly ?string $id,
        public readonly array $claims,
    ) {}
}
