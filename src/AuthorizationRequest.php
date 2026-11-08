<?php

declare(strict_types=1);

namespace Gorontalokota\Sso;

/**
 * A pending login. Store it in the user's session between the redirect to the SSO and the callback.
 */
final class AuthorizationRequest
{
    public function __construct(
        public readonly string $url,
        public readonly string $state,
        public readonly string $nonce,
        public readonly string $codeVerifier,
        public readonly int $createdAt,
        public readonly ?string $returnTo = null,
    ) {}

    /**
     * @return array{url: string, state: string, nonce: string, code_verifier: string, created_at: int, return_to: string|null}
     */
    public function toArray(): array
    {
        return [
            'url' => $this->url,
            'state' => $this->state,
            'nonce' => $this->nonce,
            'code_verifier' => $this->codeVerifier,
            'created_at' => $this->createdAt,
            'return_to' => $this->returnTo,
        ];
    }

    /**
     * @param  array<string, mixed>  $data
     */
    public static function fromArray(array $data): self
    {
        return new self(
            url: (string) ($data['url'] ?? ''),
            state: (string) ($data['state'] ?? ''),
            nonce: (string) ($data['nonce'] ?? ''),
            codeVerifier: (string) ($data['code_verifier'] ?? ''),
            createdAt: (int) ($data['created_at'] ?? 0),
            returnTo: isset($data['return_to']) ? (string) $data['return_to'] : null,
        );
    }
}
