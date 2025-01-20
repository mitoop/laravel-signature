<?php

namespace Mitoop\LaravelSignature\Key;

use Mitoop\LaravelSignature\Exceptions\UnexpectedValueException;

class KeyGenerator
{
    protected int $keyBits;

    protected int $keyType;

    public function __construct(int $keyBits = 2048, int $keyType = OPENSSL_KEYTYPE_RSA)
    {
        $this->keyBits = $keyBits;
        $this->keyType = $keyType;
    }

    /**
     * @throws UnexpectedValueException
     */
    public function generate(): array
    {
        $resource = openssl_pkey_new([
            'private_key_bits' => $this->keyBits,
            'private_key_type' => $this->keyType,
        ]);

        if ($resource === false) {
            throw new UnexpectedValueException('Failed to generate key pair: '.openssl_error_string());
        }

        openssl_pkey_export($resource, $privateKey);

        $publicKey = openssl_pkey_get_details($resource)['key'];

        return [
            $this->normalizeKey($privateKey),
            $this->normalizeKey($publicKey),
        ];
    }

    public function normalizeKey(string $key): string
    {
        $patterns = [
            '/-----BEGIN (PRIVATE|PUBLIC) KEY-----/',
            '/-----END (PRIVATE|PUBLIC) KEY-----/',
            '/\s+/',
        ];

        return preg_replace($patterns, '', $key);
    }
}
