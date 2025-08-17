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
        $keyType = $keyType->value;

        $pemHeader = "-----BEGIN $keyType KEY-----";

        if (str_starts_with($key, $pemHeader)) {
            return $key;
        }

        return "-----BEGIN $keyType KEY-----\n"
            .chunk_split($key, 64, "\n")
            ."-----END $keyType KEY-----\n";
    }
}
