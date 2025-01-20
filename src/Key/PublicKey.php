<?php

namespace Mitoop\LaravelSignature\Key;

use Mitoop\LaravelSignature\Exceptions\InvalidArgumentException;

class PublicKey extends Key
{
    /**
     * @throws InvalidArgumentException
     */
    public function getKey(): string
    {
        return $this->format($this->keyPem, static::KEY_TYPE_PUBLIC);
    }
}
