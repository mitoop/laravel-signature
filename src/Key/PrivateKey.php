<?php

namespace Mitoop\LaravelSignature\Key;

use Mitoop\LaravelSignature\Exceptions\InvalidArgumentException;

class PrivateKey extends Key
{
    /**
     * @throws InvalidArgumentException
     */
    public function getKey(): string
    {
        return $this->format($this->keyPem, static::KEY_TYPE_PRIVATE);
    }
}
