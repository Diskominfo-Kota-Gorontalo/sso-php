<?php

declare(strict_types=1);

namespace Gorontalokota\Sso\Tests;

use Gorontalokota\Sso\Cache\FileCache;
use Gorontalokota\Sso\Logout\LogoutRegistry;
use Gorontalokota\Sso\LogoutToken;
use PHPUnit\Framework\TestCase;

final class LogoutRegistryTest extends TestCase
{
    private string $directory;

    private LogoutRegistry $registry;

    protected function setUp(): void
    {
        $this->directory = sys_get_temp_dir().'/sso-registry-'.bin2hex(random_bytes(4));
        $this->registry = new LogoutRegistry(new FileCache($this->directory));
    }

    protected function tearDown(): void
    {
        array_map('unlink', glob($this->directory.'/*') ?: []);
        @rmdir($this->directory);
    }

    public function test_a_logout_with_sid_ends_only_that_session(): void
    {
        $this->registry->markEnded(new LogoutToken('sub-1', 'sid-1', time(), 'j1', []));

        self::assertTrue($this->registry->isEnded('sub-1', 'sid-1', time() - 60));
        self::assertFalse($this->registry->isEnded('sub-1', 'sid-2', time() - 60));
    }

    public function test_a_logout_without_sid_ends_every_earlier_session_of_the_account(): void
    {
        $loggedOutAt = time();
        $this->registry->markEnded(new LogoutToken('sub-1', null, $loggedOutAt, 'j2', []));

        self::assertTrue($this->registry->isEnded('sub-1', 'sid-1', $loggedOutAt - 60));
        self::assertFalse($this->registry->isEnded('sub-1', 'sid-new', $loggedOutAt + 5), 'A login after the logout stays valid.');
        self::assertFalse($this->registry->isEnded('sub-2', 'sid-1', $loggedOutAt - 60));
    }
}
