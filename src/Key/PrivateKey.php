<?php

namespace Mitoop\LaravelSignature\Key;

class PrivateKey extends Key
{
    public function getKey(): string
    {
        return $this->format($this->keyPem, KeyType::PRIVATE);
    }
}
