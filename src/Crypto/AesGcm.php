<?php

namespace Mitoop\LaravelSignature\Crypto;

use Mitoop\LaravelSignature\Exceptions\RuntimeException;
use Mitoop\LaravelSignature\Exceptions\UnexpectedValueException;

class AesGcm
{
    public const ALGO_AES_256_GCM = 'aes-256-gcm';

    public const BLOCK_SIZE = 16;

    /**
     * @throws UnexpectedValueException
     */
    public function encrypt(
        #[\SensitiveParameter]
        string $plaintext,
        #[\SensitiveParameter]
        string $key,
        string $iv = '',
        string $aad = ''
    ): string {
        $ciphertext = openssl_encrypt($plaintext, static::ALGO_AES_256_GCM, $key, OPENSSL_RAW_DATA, $iv, $tag, $aad, static::BLOCK_SIZE);

        if ($ciphertext === false) {
            throw new UnexpectedValueException('Encrypting the input $plaintext failed, please checking your $key and $iv whether or nor correct.');
        }

        return base64_encode($ciphertext.$tag);
    }

    /**
     * @throws UnexpectedValueException
     * @throws RuntimeException
     */
    public function decrypt(
        #[\SensitiveParameter]
        string $ciphertext,
        #[\SensitiveParameter]
        string $key,
        string $iv = '',
        string $aad = ''
    ): string {
        $ciphertext = base64_decode($ciphertext);
        $authTag = substr($ciphertext, $tailLength = 0 - static::BLOCK_SIZE);
        $tagLength = strlen($authTag);

        if ($tagLength > static::BLOCK_SIZE || ($tagLength < 12 && $tagLength !== 8 && $tagLength !== 4)) {
            throw new RuntimeException('The inputs `$ciphertext` incomplete, the bytes length must be one of 16, 15, 14, 13, 12, 8 or 4.');
        }

        $plaintext = openssl_decrypt(substr($ciphertext, 0, $tailLength), static::ALGO_AES_256_GCM, $key, OPENSSL_RAW_DATA, $iv, $authTag, $aad);

        if ($plaintext === false) {
            throw new UnexpectedValueException('Decrypting the input $ciphertext failed, please checking your $key and $iv whether or nor correct.');
        }

        return $plaintext;
    }
}
