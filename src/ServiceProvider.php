<?php

namespace Mitoop\LaravelSignature;

use Illuminate\Support\ServiceProvider as LaravelServiceProvider;
use Mitoop\LaravelSignature\Crypto\AesGcm;
use Mitoop\LaravelSignature\Crypto\Rsa;
use Mitoop\LaravelSignature\Http\Client;
use Mitoop\LaravelSignature\Key\KeyGenerator;
use Mitoop\LaravelSignature\Signer\SignType;
use Mitoop\LaravelSignature\Validation\Context;
use Mitoop\LaravelSignature\Validation\Validator;

class ServiceProvider extends LaravelServiceProvider
{
    public $bindings = [
        KeyGenerator::class => KeyGenerator::class,
        Rsa::class => Rsa::class,
        AesGcm::class => AesGcm::class,
    ];

    public function register(): void
    {
        $this->app->singleton(Validator::class, function () {
            return new Validator(SignType::map());
        });

        $this->app->singleton(Client::class, function () {
            return tap(new Client(SignType::map()),
                fn (Client $client) => $client->useSigner(SignType::RSA2048_SHA256->formatWithBrand())
            );
        });

        $this->app->singleton(Context::class, function () {
            return new Context(config('signature.brand'));
        });
    }

    public function boot(): void
    {
        $path = realpath(__DIR__.'/../config/signature.php');

        $this->mergeConfigFrom($path, 'signature');

        if ($this->app->runningInConsole()) {
            $this->publishes([$path => config_path('signature.php')], 'config');
        }
    }
}
