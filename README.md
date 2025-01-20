# Laravel Signature

Laravel Signature is a robust and flexible package for handling API signature validation and generation. It supports multiple signing methods and can be easily extended to fit your application's needs.

## Features

- Supports RSA2048-SHA256 and HMAC-SHA256 signature methods.
- Customizable brand prefixes for signatures.
- Provides a flexible resolver interface for fetching application-specific configurations.
- Easily integrates with Laravel's service container.

## Installation

Install the package via Composer:

```bash
composer require mitoop/laravel-signature
```

## Configuration

Publish the configuration file:

```bash
php artisan vendor:publish --tag=config --provider="Mitoop\\LaravelSignature\\ServiceProvider"
```

This will create a `config/signature.php` file. Customize it as needed:

```php
return [
    'brand' => 'MAXPAY',
    'max_clock_offset' => 300,
    'http_timeout' => 60,
];
```
