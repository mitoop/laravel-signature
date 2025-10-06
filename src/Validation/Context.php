<?php

namespace Mitoop\LaravelSignature\Validation;

class Context
{
    protected const SECURE_PREFIX = '1a2fc26d';

    public function __construct(protected string $prefix) {}

    public function set(string $key, mixed $value): void
    {
        request()->attributes->set($this->secureKey($key), $value);
    }

    public function get(string $key, $default = null): mixed
    {
        return request()->attributes->get($this->secureKey($key), $default);
    }

    public function has(string $key): bool
    {
        return request()->attributes->has($this->secureKey($key));
    }

    protected function secureKey(string $key): string
    {
        return sprintf('%s.%s.%s', strtolower($this->prefix), self::SECURE_PREFIX, $key);
    }
}
