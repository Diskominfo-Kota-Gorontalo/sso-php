<?php

declare(strict_types=1);

namespace Gorontalokota\Sso\Cache;

use DateInterval;
use DateTimeImmutable;
use Psr\SimpleCache\CacheInterface;

/**
 * In-memory PSR-16 cache (per request). Default when no cache is given; fine for discovery/JWKS,
 * NOT suitable for the logout registry, which must be shared between requests.
 */
final class ArrayCache implements CacheInterface
{
    /** @var array<string, array{value: mixed, expires: int|null}> */
    private array $items = [];

    public function get(string $key, mixed $default = null): mixed
    {
        $item = $this->items[$key] ?? null;

        if ($item === null || ($item['expires'] !== null && $item['expires'] <= time())) {
            unset($this->items[$key]);

            return $default;
        }

        return $item['value'];
    }

    public function set(string $key, mixed $value, null|int|DateInterval $ttl = null): bool
    {
        $this->items[$key] = ['value' => $value, 'expires' => self::expiry($ttl)];

        return true;
    }

    public function delete(string $key): bool
    {
        unset($this->items[$key]);

        return true;
    }

    public function clear(): bool
    {
        $this->items = [];

        return true;
    }

    /**
     * @param  iterable<string>  $keys
     * @return iterable<string, mixed>
     */
    public function getMultiple(iterable $keys, mixed $default = null): iterable
    {
        $result = [];

        foreach ($keys as $key) {
            $result[$key] = $this->get($key, $default);
        }

        return $result;
    }

    /**
     * @param  iterable<string, mixed>  $values
     */
    public function setMultiple(iterable $values, null|int|DateInterval $ttl = null): bool
    {
        foreach ($values as $key => $value) {
            $this->set((string) $key, $value, $ttl);
        }

        return true;
    }

    /**
     * @param  iterable<string>  $keys
     */
    public function deleteMultiple(iterable $keys): bool
    {
        foreach ($keys as $key) {
            $this->delete($key);
        }

        return true;
    }

    public function has(string $key): bool
    {
        return $this->get($key, $this) !== $this;
    }

    public static function expiry(null|int|DateInterval $ttl): ?int
    {
        if ($ttl === null) {
            return null;
        }

        if ($ttl instanceof DateInterval) {
            return (new DateTimeImmutable)->add($ttl)->getTimestamp();
        }

        return time() + $ttl;
    }
}
