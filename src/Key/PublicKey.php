<?php

namespace Mitoop\LaravelSignature\Key;

class PublicKey extends Key
{
    public function getKey(): string
    {
        return $this->format($this->keyPem);
    }
}
