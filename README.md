# gorontalokota/sso-php

Client OpenID Connect SSO Pemerintah Kota Gorontalo untuk PHP 8.1+. Dipakai langsung di PHP native dan CodeIgniter 3, dan menjadi dasar paket Laravel dan CodeIgniter 4.

```bash
composer require gorontalokota/sso-php
```

## Cara paling cepat: `SsoAuth` (sesi PHP)

```php
use Gorontalokota\Sso\Cache\FileCache;
use Gorontalokota\Sso\Logout\LogoutRegistry;
use Gorontalokota\Sso\Native\SsoAuth;
use Gorontalokota\Sso\SsoClient;
use Gorontalokota\Sso\SsoConfig;

$config = SsoConfig::fromArray([
    'realm' => 'internal',                      // internal (ASN) atau external (masyarakat)
    'client_id' => getenv('SSO_CLIENT_ID'),
    'client_secret' => getenv('SSO_CLIENT_SECRET'),
    'scopes' => 'openid profile email',
    'redirect_uri' => 'https://aplikasi.go.id/callback.php',
    'post_logout_redirect_uri' => 'https://aplikasi.go.id/',
]);
$cache = new FileCache(__DIR__.'/storage/sso-cache');   // di luar folder publik
$sso = new SsoAuth(new SsoClient($config, null, $cache), new LogoutRegistry($cache));
```

| File | Isi |
|---|---|
| `login.php` | `$sso->redirectToLogin($_GET['return_to'] ?? null);` |
| `callback.php` | `$user = $sso->handleCallback($_GET); header('Location: '.$sso->pullReturnTo('/'));` |
| halaman terlindungi | `$user = $sso->user() ?? $sso->redirectToLogin($_SERVER['REQUEST_URI']);` |
| `logout.php` (POST + CSRF) | `header('Location: '.$sso->logout());` |
| `backchannel-logout.php` | `http_response_code($sso->handleBackchannelLogout($_POST['logout_token'] ?? null));` |

Contoh lengkap ada di [examples/php-native](../../examples/php-native).

`$user` adalah `SsoUser`: `sub`, `name`, `email`, `nip()`, `nik()`, `phoneNumber()`, `employment()`, `verificationLevel()`, `claim('nama_klaim')`.

## API tingkat rendah: `SsoClient`

```php
$request = $client->createAuthorizationRequest(['prompt' => 'login'], '/kembali-ke');  // simpan $request->toArray() di sesi
$tokens  = $client->handleCallback($_GET, AuthorizationRequest::fromArray($simpanan)); // TokenSet
$tokens  = $client->refresh($tokens->refreshToken);
$claims  = $client->userinfo($tokens->accessToken);
$url     = $client->logoutUrl($tokens->idToken);
$claims  = $client->verifyAccessToken($bearer, ['employee']);   // untuk API
$logout  = $client->verifyLogoutToken($_POST['logout_token']);
```

Kesalahan dilempar sebagai turunan `Gorontalokota\Sso\Exception\SsoException`: `AuthorizationDeniedException` (pengguna menolak), `InvalidStateException`, `TokenValidationException`, `InsufficientScopeException`, `HttpException`.

## Cache

`SsoClient` menyimpan discovery dan JWKS di cache PSR-16. Tanpa cache, keduanya diambil ulang setiap request. `LogoutRegistry` **wajib** memakai cache yang bertahan antar request dan dipakai bersama semua server: `FileCache` untuk satu server, adapter PSR-16 Redis untuk banyak server.

## Pengujian

`Gorontalokota\Sso\Testing\FakeProvider` meniru server SSO (discovery, JWKS, token, userinfo) dan membuat ID token, access token, serta logout token yang ditandatangani:

```php
$provider = new FakeProvider;
$client = new SsoClient($config, $provider->http());
$client->verifyAccessToken($provider->accessToken());
```
