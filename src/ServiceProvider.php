<?php

namespace Mitoop\LaravelSignature;

use Illuminate\Support\ServiceProvider as LaravelServiceProvider;
use Mitoop\LaravelSignature\Crypto\AesGcm;
use Mitoop\LaravelSignature\Crypto\Rsa;
use Mitoop\LaravelSignature\Crypto\RsaAesGcm;
use Mitoop\LaravelSignature\Http\Client;
use Mitoop\LaravelSignature\Key\KeyGeneratorFactory;
use Mitoop\LaravelSignature\Signer\SignHeaderBuilder;
use Mitoop\LaravelSignature\Validation\Context;
use Mitoop\LaravelSignature\Validation\Validator;

class ServiceProvider extends LaravelServiceProvider
{
    public $singletons = [
        SignHeaderBuilder::class => SignHeaderBuilder::class,
        Client::class => Client::class,
        Validator::class => Validator::class,
        KeyGeneratorFactory::class => KeyGeneratorFactory::class,
        Rsa::class => Rsa::class,
        AesGcm::class => AesGcm::class,
        RsaAesGcm::class => RsaAesGcm::class,
    ];

    public function register(): void
    {
        $this->app->singleton(Context::class, function () {
            return new Context(config('signature.brand'));
        });

        $this->mergeConfigFrom(__DIR__.'/../config/signature.php', 'signature');
    }

    public function boot(): void
    {
        if ($this->app->runningInConsole()) {
            $this->publishes([__DIR__.'/../config/signature.php' => config_path('signature.php')], 'config');
        }
    }
}
