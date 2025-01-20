<?php

namespace Mitoop\LaravelSignature\Validation;

class Context
{
    public function __construct(protected string $prefix) {}

    public function set(string $key, mixed $value): void
    {
        request()->attributes->set($this->addPrefix($key), $value);
    }

    public function get(string $key, $default = null): mixed
    {
        return request()->attributes->get($this->addPrefix($key), $default);
    }

    public function has(string $key): bool
    {
        return request()->attributes->has($this->addPrefix($key));
    }

    protected function addPrefix(string $key): string
    {
        return sprintf('%s.1a2fc26d.%s', $this->prefix, $key);
    }
}
