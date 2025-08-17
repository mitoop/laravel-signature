<?php

namespace Mitoop\LaravelSignature\Key\Generators;

use Mitoop\LaravelSignature\Exceptions\RuntimeException;
use Mitoop\LaravelSignature\Key\KeyType;
use SodiumException;

class Ed25519KeyGenerator implements KeyGeneratorInterface
{
    /**
     * @throws SodiumException
     * @throws RuntimeException
     */
    public function generate(): array
    {
        if (PHP_VERSION_ID >= 80400 && defined('OPENSSL_KEYTYPE_ED25519')) {
            return $this->generateWithOpenssl();
        }

        return $this->generateWithSodium();
    }

    /**
     * @throws RuntimeException
     */
    protected function generateWithOpenssl(): array
    {
        $config = [
            'private_key_type' => constant('OPENSSL_KEYTYPE_ED25519'),
        ];

        $keyResource = openssl_pkey_new($config);

        if ($keyResource === false) {
            $errors = [];
            while ($msg = openssl_error_string()) {
                $errors[] = $msg;
            }
            throw new RuntimeException(
                'Failed to generate Ed25519 keypair with OpenSSL: '.implode(' | ', $errors)
            );
        }

        openssl_pkey_export($keyResource, $privateKeyPem);

        $details = openssl_pkey_get_details($keyResource);

        return [$privateKeyPem, $details['key']];
    }

    /**
     * @throws SodiumException
     */
    protected function generateWithSodium(): array
    {
        $keypair = sodium_crypto_sign_keypair();
        $privateKey = sodium_crypto_sign_secretkey($keypair);
        $publicKey = sodium_crypto_sign_publickey($keypair);

        return [
            $this->wrapKey($privateKey, KeyType::PRIVATE),
            $this->wrapKey($publicKey),
        ];
    }

    protected function wrapKey(string $rawKey, KeyType $keyType = KeyType::PUBLIC): string
    {
        $prefix = $this->getDerPrefix($keyType);
        $fullKey = $prefix.$rawKey;
        $encoded = chunk_split(base64_encode($fullKey), 64, "\n");
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
