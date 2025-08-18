# Laravel Signature

Laravel Signature is a robust and flexible package for handling API signature validation and generation. It supports multiple signing methods and can be easily extended to fit your application's needs.

## ✨ Features

- Supports **SHA256-RSA2048**, **SHA256-HMAC**, and **ED25519** signature methods.
- Customizable brand prefixes for signatures.
- Provides a flexible resolver interface for fetching application-specific configurations.
- Easily integrates with Laravel's service container.

## 📦 Installation

Install the package via Composer:

```bash
composer require mitoop/laravel-signature
```

## ⚙️ Configuration

Publish the configuration file:

```bash
php artisan vendor:publish --tag=config --provider="Mitoop\\LaravelSignature\\ServiceProvider"
```

This will create a `config/signature.php` file. Customize it as needed:

```php
return [
    'brand' => 'your_brand',
    'max_clock_offset' => 300,
    'http_timeout' => 60,
];
```

## 🛡️Signature Validation Middleware
Laravel Signature provides a built-in middleware called ValidateSignature 
that verifies incoming API requests to ensure 
they are properly signed and not tampered with or replayed.

You can also create a custom middleware if you need more control over how the signature is verified or logged.
#### ✅ Registering the Middleware
```php
use Mitoop\LaravelSignature\Middlewares\ValidateSignature;

Route::middleware([ValidateSignature::class])->group(function () {
    Route::post('/api/data/cities', [CityController::class, 'index']);
});
```

## 🔄 Making Callback Requests
Laravel Signature also provides a Client class to help you send signed HTTP requests, which is useful for performing callback notifications.
#### ✅ Example: Sending a Signed Callback
```php
use Mitoop\LaravelSignature\Http\Client;

$response = app(Client::class)->post('https://outer-service.com/api/notify', [
    'order_id' => '123456',
    'status' => 'success',
], 'platform-private-key');
```

## References
- [WechatPay-API-v3](https://wechatpay-api.gitbook.io/wechatpay-api-v3)
- [Alipay-open-v3](https://opendocs.alipay.com/open-v3/054kaq)

