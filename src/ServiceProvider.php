<?php

namespace Mitoop\LaravelSignature;

use Illuminate\Support\ServiceProvider as LaravelServiceProvider;
use Mitoop\LaravelSignature\Crypto\AesGcm;
use Mitoop\LaravelSignature\Crypto\Rsa;
use Mitoop\LaravelSignature\Http\Client;
use Mitoop\LaravelSignature\Key\KeyGeneratorFactory;
use Mitoop\LaravelSignature\Signer\SignatureHeaderBuilder;
use Mitoop\LaravelSignature\Signer\SignatureHeaderBuilderFactory;
use Mitoop\LaravelSignature\Signer\SignType;
use Mitoop\LaravelSignature\Validation\Context;
use Mitoop\LaravelSignature\Validation\Validator;

class ServiceProvider extends LaravelServiceProvider
{
    public $bindings = [
        KeyGeneratorFactory::class => KeyGeneratorFactory::class,
        Rsa::class => Rsa::class,
        AesGcm::class => AesGcm::class,
        SignatureHeaderBuilder::class => SignatureHeaderBuilder::class,
    ];

    public $singletons = [
        Client::class => Client::class,
        SignatureHeaderBuilderFactory::class => SignatureHeaderBuilderFactory::class,
    ];

    public function register(): void
    {
        $this->app->singleton(Validator::class, function () {
            return new Validator(SignType::map());
        });

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
