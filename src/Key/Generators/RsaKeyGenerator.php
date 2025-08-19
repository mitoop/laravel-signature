<?php

namespace Mitoop\LaravelSignature\Key\Generators;

use Mitoop\LaravelSignature\Exceptions\RuntimeException;

class RsaKeyGenerator implements KeyGeneratorInterface
{
    protected int $keyBits;

    public function __construct(int $keyBits = 2048)
    {
        $this->keyBits = $keyBits;
    }

    /**
     * @throws RuntimeException
     */
    public function generate(): array
    {
        $resource = openssl_pkey_new([
            'private_key_bits' => $this->keyBits,
            'private_key_type' => OPENSSL_KEYTYPE_RSA,
        ]);

        if ($resource === false) {
            throw new RuntimeException('Failed to generate key pair: '.openssl_error_string());
        }

        openssl_pkey_export($resource, $privateKey);

        $publicKey = openssl_pkey_get_details($resource)['key'];

        return [
            $privateKey,
            $publicKey,
        ];
    }
}
