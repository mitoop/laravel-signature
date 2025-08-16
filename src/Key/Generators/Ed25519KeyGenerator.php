<?php

namespace Mitoop\LaravelSignature\Key\Generators;

use Mitoop\LaravelSignature\Key\KeyType;
use SodiumException;

class Ed25519KeyGenerator implements KeyGeneratorInterface
{
    /**
     * @throws SodiumException
     */
    public function generate(): array
    {
        $keypair = sodium_crypto_sign_keypair();
        $privateKey = sodium_crypto_sign_secretkey($keypair);
        $publicKey = sodium_crypto_sign_publickey($keypair);

        return [
            $this->wrapKey($privateKey, KeyType::PRIVATE),
            $this->wrapKey($publicKey),
        ];
    }

    public function wrapKey(string $rawKey, KeyType $keyType = KeyType::PUBLIC): string
    {
        $prefix = $this->getDerPrefix($keyType);
        $fullKey = $prefix.$rawKey;
        $encoded = wordwrap(base64_encode($fullKey), 64, "\n", true);
        $type = $keyType->value;

        return "-----BEGIN {$type} KEY-----\n"
            .$encoded
            ."-----END {$type} KEY-----\n";
    }

    protected function getDerPrefix(KeyType $keyType): string
    {
        return match ($keyType) {
            KeyType::PRIVATE => hex2bin('302e020100300506032b657004220420'), // PKCS#8 私钥
            KeyType::PUBLIC => hex2bin('302a300506032b6570032100'), // X.509 公钥
        };
    }
}
