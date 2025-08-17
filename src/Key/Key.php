<?php

namespace Mitoop\LaravelSignature\Key;

use Mitoop\LaravelSignature\Exceptions\InvalidArgumentException;

abstract class Key
{
    protected const KEY_TYPE_PUBLIC = 'PUBLIC';

    protected const KEY_TYPE_PRIVATE = 'PRIVATE';

    public function __construct(protected string $keyPem) {}

    public function __toString(): string
    {
        return $this->getKey();
    }

    abstract public function getKey(): string;

    /**
     * @throws InvalidArgumentException
     */
    protected function format($key, $keyType): string
    {
        if (! in_array($keyType = strtoupper($keyType), [static::KEY_TYPE_PUBLIC, static::KEY_TYPE_PRIVATE], true)) {
            throw new InvalidArgumentException("Invalid key type: $keyType. Valid types are 'PUBLIC' or 'PRIVATE'.");
        }

        return "-----BEGIN $keyType KEY-----\n"
            .chunk_split($key, 64, "\n")
            ."-----END $keyType KEY-----\n";
    }
}
