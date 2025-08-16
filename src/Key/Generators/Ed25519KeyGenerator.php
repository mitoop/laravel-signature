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

        $pkcs8PrivatePrefix = hex2bin(
            '302e020100300506032b657004220420'
        );

        $x509PublicPrefix = hex2bin(
            '302a300506032b6570032100'
        );

        return [
            $this->wrapKey($pkcs8PrivatePrefix.$privateKey, KeyType::PRIVATE),
            $this->wrapKey($x509PublicPrefix.$publicKey),
        ];
    }

    public function wrapKey(string $key, KeyType $keyType = KeyType::PUBLIC): string
    {
        $type = $keyType->value;

        $encodedKey = wordwrap(base64_encode($key), 64, "\n", true);

        return "-----BEGIN {$type} KEY-----\n"
            .$encodedKey
            ."-----END {$type} KEY-----\n";
    }
}
