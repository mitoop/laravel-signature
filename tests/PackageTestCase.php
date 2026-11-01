<?php

declare(strict_types=1);

use Illuminate\Cache\CacheServiceProvider;
use Illuminate\Config\Repository;
use Illuminate\Events\EventServiceProvider;
use Illuminate\Filesystem\FilesystemServiceProvider;
use Illuminate\Foundation\Application;
use Illuminate\Routing\RoutingServiceProvider;
use Illuminate\Support\Facades\Facade;
use Illuminate\View\ViewServiceProvider;
use Mitoop\LaravelSignature\ServiceProvider;
use PHPUnit\Framework\TestCase;

abstract class PackageTestCase extends TestCase
{
    protected Application $app;

    protected function setUp(): void
    {
        $compiled = sys_get_temp_dir().'/laravel-signature-views';

        if (! is_dir($compiled)) {
            mkdir($compiled, 0777, true);
        }

        $this->app = new Application(__DIR__);
        $this->app->instance('config', new Repository([
            'app' => [
                'key' => 'base64:'.base64_encode(random_bytes(32)),
                'cipher' => 'AES-256-CBC',
            ],
            'view' => [
                'paths' => [],
                'compiled' => $compiled,
            ],
            'cache' => [
                'default' => 'array',
                'prefix' => 'laravel-signature-test',
                'stores' => [
                    'array' => ['driver' => 'array', 'serialize' => false],
                ],
            ],
            'signature' => [
                'brand' => 'your_brand',
                'max_clock_offset' => 300,
                'http_timeout' => 5,
                'skip_clock_check' => false,
                'skip_nonce_check' => false,
            ],
        ]));
        $this->app->register(EventServiceProvider::class);
        $this->app->register(FilesystemServiceProvider::class);
        $this->app->register(ViewServiceProvider::class);
        $this->app->register(RoutingServiceProvider::class);
        $this->app->register(CacheServiceProvider::class);
        $this->app->register(ServiceProvider::class);
        Facade::clearResolvedInstances();
        Facade::setFacadeApplication($this->app);
    }

    protected function tearDown(): void
    {
        Facade::clearResolvedInstances();
        Facade::setFacadeApplication(null);
        $this->app->flush();
        Application::setInstance(null);
    }
}
