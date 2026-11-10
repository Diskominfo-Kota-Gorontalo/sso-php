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

    /** NIP (internal realm, scope "employee" or "profile"). */
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
     * Internal realm employment data (scope "employee").
     *
     * Reads the English claim names and falls back to the legacy Indonesian names sent by older SSO servers.
     *
     * @return array{organization_code: string|null, organization_name: string|null, position: string|null, grade: string|null, employment_status: string|null}
     */
    public function employment(): array
    {
        return [
            'organization_code' => $this->firstClaim('organization_code', 'opd_kode'),
            'organization_name' => $this->firstClaim('organization_name', 'opd_nama'),
            'position' => $this->firstClaim('position', 'jabatan'),
            'grade' => $this->firstClaim('grade', 'golongan'),
            'employment_status' => $this->firstClaim('employment_status', 'status_kepegawaian'),
        ];
    }

    /** External realm verification level: "L1" (self-registered) or "L2" (NIK checked at a service counter). */
    public function verificationLevel(): ?string
    {
        return $this->firstClaim('verification_level', 'tingkat_akun');
    }

    private function firstClaim(string ...$names): ?string
    {
        foreach ($names as $name) {
            if (isset($this->claims[$name]) && $this->claims[$name] !== '') {
                return (string) $this->claims[$name];
            }
        }

        return null;
    }

    /**
     * @return array<string, mixed>
     */
    public function toArray(): array
    {
        return $this->claims;
    }
}
