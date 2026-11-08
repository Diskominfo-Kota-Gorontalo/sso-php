<?php

declare(strict_types=1);

namespace Gorontalokota\Sso;

/**
 * The signed-in person as described by ID token / userinfo claims.
 *
 * Link local accounts by $sub. NIP/NIK should only be used once to match an existing local account, then store $sub.
 */
final class SsoUser
{
    /**
     * @param  array<string, mixed>  $claims
     */
    public function __construct(
        public readonly string $sub,
        public readonly ?Realm $realm,
        public readonly ?string $name,
        public readonly ?string $preferredUsername,
        public readonly ?string $email,
        public readonly bool $emailVerified,
        public readonly ?string $sessionId,
        public readonly ?int $authTime,
        public readonly array $claims,
    ) {}

    /**
     * @param  array<string, mixed>  $claims
     */
    public static function fromClaims(array $claims): self
    {
        $string = static fn (string $key): ?string => isset($claims[$key]) && $claims[$key] !== '' ? (string) $claims[$key] : null;

        return new self(
            sub: (string) ($claims['sub'] ?? ''),
            realm: isset($claims['iss']) ? Realm::fromIssuer((string) $claims['iss']) : null,
            name: $string('name'),
            preferredUsername: $string('preferred_username'),
            email: $string('email'),
            emailVerified: (bool) ($claims['email_verified'] ?? false),
            sessionId: $string('sid'),
            authTime: isset($claims['auth_time']) ? (int) $claims['auth_time'] : null,
            claims: $claims,
        );
    }

    public function claim(string $name, mixed $default = null): mixed
    {
        return $this->claims[$name] ?? $default;
    }

    public function isInternal(): bool
    {
        return $this->realm === Realm::Internal;
    }

    public function isExternal(): bool
    {
        return $this->realm === Realm::External;
    }

    /** NIP (internal realm, scope "asn" or "profile"). */
    public function nip(): ?string
    {
        $nip = $this->claims['nip'] ?? ($this->isInternal() ? $this->preferredUsername : null);

        return $nip !== null ? (string) $nip : null;
    }

    /** NIK (external realm, restricted scope "nik"). */
    public function nik(): ?string
    {
        return isset($this->claims['nik']) ? (string) $this->claims['nik'] : null;
    }

    public function phoneNumber(): ?string
    {
        return isset($this->claims['phone_number']) ? (string) $this->claims['phone_number'] : null;
    }

    /**
     * Internal realm employment data (scope "asn").
     *
     * @return array{opd_kode: string|null, opd_nama: string|null, jabatan: string|null, golongan: string|null, status_kepegawaian: string|null}
     */
    public function employment(): array
    {
        $value = fn (string $key): ?string => isset($this->claims[$key]) ? (string) $this->claims[$key] : null;

        return [
            'opd_kode' => $value('opd_kode'),
            'opd_nama' => $value('opd_nama'),
            'jabatan' => $value('jabatan'),
            'golongan' => $value('golongan'),
            'status_kepegawaian' => $value('status_kepegawaian'),
        ];
    }

    /** External realm verification level: "L1" (self-registered) or "L2" (NIK checked at a service counter). */
    public function verificationLevel(): ?string
    {
        return isset($this->claims['tingkat_akun']) ? (string) $this->claims['tingkat_akun'] : null;
    }

    /**
     * @return array<string, mixed>
     */
    public function toArray(): array
    {
        return $this->claims;
    }
}
