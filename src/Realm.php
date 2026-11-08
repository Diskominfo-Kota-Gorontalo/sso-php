<?php

declare(strict_types=1);

namespace Gorontalokota\Sso;

/**
 * SSO realms. Each realm is a separate OpenID Connect issuer.
 */
enum Realm: string
{
    /** ASN (civil servants) of Pemerintah Kota Gorontalo. */
    case Internal = 'internal';

    /** Citizens (masyarakat). */
    case External = 'external';

    public const DEFAULT_BASE_URL = 'https://sso.gorontalokota.go.id';

    public function issuer(string $baseUrl = self::DEFAULT_BASE_URL): string
    {
        return rtrim($baseUrl, '/').'/'.$this->value;
    }

    public static function fromIssuer(string $issuer): ?self
    {
        foreach (self::cases() as $realm) {
            if (str_ends_with(rtrim($issuer, '/'), '/'.$realm->value)) {
                return $realm;
            }
        }

        return null;
    }
}
