<?php

namespace Mitoop\LaravelSignature\Crypto;

use Mitoop\LaravelSignature\Exceptions\InvalidArgumentException;

class Rsa
{
    /**
     * @throws InvalidArgumentException
     */
    public function encrypt(string $plaintext, #[\SensitiveParameter] string $secretKey): string
    {
        if (openssl_public_encrypt($plaintext, $encrypted, $secretKey, OPENSSL_PKCS1_OAEP_PADDING)) {
            return base64_encode($encrypted);
        }

        throw new InvalidArgumentException('Encrypting the content failed. Please verify that the provided public key is valid.');
    }

    /**
     * @throws InvalidArgumentException
     */
    public function decrypt(string $cipherText, #[\SensitiveParameter] string $secretKey): string
    {
        if (openssl_private_decrypt(base64_decode($cipherText), $decrypted, $secretKey, OPENSSL_PKCS1_OAEP_PADDING)) {
            return $decrypted;
        }

        throw new InvalidArgumentException('Decrypting the content failed. Please verify that the provided private key is valid.');
    }
}
