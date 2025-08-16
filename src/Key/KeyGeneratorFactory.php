<?php

namespace Mitoop\LaravelSignature\Key;

use Mitoop\LaravelSignature\Key\Generators\Ed25519KeyGenerator;
use Mitoop\LaravelSignature\Key\Generators\KeyGeneratorInterface;
use Mitoop\LaravelSignature\Key\Generators\RsaKeyGenerator;

class KeyGeneratorFactory
{
    public function make(KeyAlgo $algo, int $keyBits = 2048): KeyGeneratorInterface
    {
        return match ($algo) {
            KeyAlgo::RSA => new RsaKeyGenerator($keyBits),
            KeyAlgo::ED25519 => new Ed25519KeyGenerator,
        };
    }
}
