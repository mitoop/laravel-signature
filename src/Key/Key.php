<?php

namespace Mitoop\LaravelSignature\Key;

abstract class Key
{
    public function __construct(protected string $keyPem) {}

    public function __toString(): string
    {
        return $this->getKey();
    }

    abstract public function getKey(): string;

    protected function format($key, KeyType $keyType = KeyType::PUBLIC): string
    {
        $key = trim($key);

        if (str_starts_with($key, '-----BEGIN ')) {
            return $key;
        }

        $key = preg_replace('/\s+/', '', $key) ?? $key;
        $label = $keyType->value;

        return "-----BEGIN {$label} KEY-----\n"
            .chunk_split($key, 64, "\n")
            ."-----END {$label} KEY-----\n";
    }
}
