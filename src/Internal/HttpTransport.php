<?php

declare(strict_types=1);

namespace Gorontalokota\Sso\Internal;

use Gorontalokota\Sso\Exception\HttpException;
use GuzzleHttp\ClientInterface;
use GuzzleHttp\Exception\GuzzleException;
use Psr\Http\Message\ResponseInterface;

/**
 * @internal JSON/form helpers over Guzzle with consistent errors.
 */
final class HttpTransport
{
    public function __construct(
        private readonly ClientInterface $http,
        private readonly float $timeout,
    ) {}

    /**
     * @param  array<string, string>  $headers
     * @return array<string, mixed>
     */
    public function getJson(string $url, array $headers = []): array
    {
        return $this->json($this->send('GET', $url, ['headers' => ['Accept' => 'application/json', ...$headers]]), $url);
    }

    /**
     * @param  array<string, string>  $form
     * @param  array<string, string>  $headers
     * @return array<string, mixed>
     */
    public function postForm(string $url, array $form, array $headers = [], bool $expectJson = true): array
    {
        $response = $this->send('POST', $url, ['form_params' => $form, 'headers' => ['Accept' => 'application/json', ...$headers]]);

        return $expectJson ? $this->json($response, $url) : [];
    }

    /**
     * @param  array<string, mixed>  $options
     */
    private function send(string $method, string $url, array $options): ResponseInterface
    {
        try {
            $response = $this->http->request($method, $url, [...$options, 'timeout' => $this->timeout, 'http_errors' => false, 'allow_redirects' => false]);
        } catch (GuzzleException $exception) {
            throw new HttpException("SSO request to {$url} failed: {$exception->getMessage()}", 0, $exception);
        }

        if ($response->getStatusCode() >= 400) {
            $body = json_decode((string) $response->getBody(), true);
            $error = is_array($body) ? trim(($body['error'] ?? '').' '.($body['error_description'] ?? $body['message'] ?? '')) : '';

            throw new HttpException("SSO {$method} {$url} answered HTTP {$response->getStatusCode()}".($error !== '' ? ": {$error}" : '.'), $response->getStatusCode());
        }

        return $response;
    }

    /**
     * @return array<string, mixed>
     */
    private function json(ResponseInterface $response, string $url): array
    {
        $data = json_decode((string) $response->getBody(), true);

        if (! is_array($data)) {
            throw new HttpException("SSO response from {$url} is not valid JSON.");
        }

        return $data;
    }
}
