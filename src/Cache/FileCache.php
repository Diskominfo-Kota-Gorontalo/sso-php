<?php

declare(strict_types=1);

namespace Gorontalokota\Sso\Cache;

use DateInterval;
use Psr\SimpleCache\CacheInterface;
use RuntimeException;

/**
 * Minimal file-based PSR-16 cache for PHP native / CodeIgniter 3 apps without Redis or a framework cache.
 * Shared between requests on one server; use Redis (any PSR-16 adapter) when the app runs on several servers.
 */
final class FileCache implements CacheInterface
{
    public function __construct(private readonly string $directory)
    {
        if (! is_dir($directory) && ! @mkdir($directory, 0770, true) && ! is_dir($directory)) {
            throw new RuntimeException("Cannot create SSO cache directory {$directory}.");
        }
    }

    public function get(string $key, mixed $default = null): mixed
    {
        $contents = @file_get_contents($this->path($key));

        if ($contents === false) {
            return $default;
        }

        $item = @unserialize($contents, ['allowed_classes' => false]);

        if (! is_array($item) || ($item['expires'] !== null && $item['expires'] <= time())) {
            @unlink($this->path($key));

            return $default;
        }

        return $item['value'];
    }

    public function set(string $key, mixed $value, null|int|DateInterval $ttl = null): bool
    {
        $path = $this->path($key);
        $temporary = $path.'.'.bin2hex(random_bytes(4)).'.tmp';

        if (@file_put_contents($temporary, serialize(['value' => $value, 'expires' => ArrayCache::expiry($ttl)]), LOCK_EX) === false) {
            return false;
        }

        return @rename($temporary, $path);
    }

    public function delete(string $key): bool
    {
        @unlink($this->path($key));

        return true;
    }

    public function clear(): bool
    {
        foreach (glob($this->directory.'/sso_*.cache') ?: [] as $file) {
            @unlink($file);
        }

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
        $ok = true;

        foreach ($values as $key => $value) {
            $ok = $this->set((string) $key, $value, $ttl) && $ok;
        }

        return $ok;
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

    private function path(string $key): string
    {
        return $this->directory.'/sso_'.sha1($key).'.cache';
    }
}
