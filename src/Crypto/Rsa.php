<?php

namespace Mitoop\LaravelSignature\Crypto;

use Mitoop\LaravelSignature\Exceptions\RuntimeException;
use Mitoop\LaravelSignature\Key\PrivateKey;
use Mitoop\LaravelSignature\Key\PublicKey;
use SensitiveParameter;

class Rsa
{
    /**
     * @throws RuntimeException
     */
    public function encrypt(string $plaintext, #[SensitiveParameter] string $publicKey): string
    {
        if (openssl_public_encrypt($plaintext, $encrypted, (new PublicKey($publicKey))->getKey(), OPENSSL_PKCS1_OAEP_PADDING)) {
            return base64_encode($encrypted);
        }

        throw new RuntimeException('Encrypting the content failed. Please verify that the provided public key is valid.');
    }

    /**
     * @throws RuntimeException
     */
    public function decrypt(string $cipherText, #[SensitiveParameter] string $privateKey): string
    {
        $decoded = base64_decode($cipherText, true);
        if ($decoded === false) {
            throw new RuntimeException('Base64 decoding failed. Invalid ciphertext.');
        }

        if (openssl_private_decrypt($decoded, $decrypted, (new PrivateKey($privateKey))->getKey(), OPENSSL_PKCS1_OAEP_PADDING)) {
            return $decrypted;
        }

        throw new RuntimeException('Decrypting the content failed. Please verify that the provided private key is valid.');
    }
}
