<?php

namespace Mitoop\LaravelSignature\Crypto;

use Mitoop\LaravelSignature\Exceptions\RuntimeException;
use Random\RandomException;
use SensitiveParameter;

class AesGcm
{
    public const ALGO = 'aes-256-gcm';

    public const TAG_LENGTH = 16;

    /**
     * @throws RuntimeException
     * @throws RandomException
     */
    public function encrypt(string $plaintext, #[SensitiveParameter] string $key, string $associatedData = ''): array
    {
        $iv = random_bytes(openssl_cipher_iv_length(static::ALGO));

        $tag = '';
        $ciphertext = openssl_encrypt(
            $plaintext,
            static::ALGO,
            $key,
            OPENSSL_RAW_DATA,
            $iv,
            $tag,
            $associatedData,
            static::TAG_LENGTH
        );

        if ($ciphertext === false) {
            throw new RuntimeException('Encrypting the input $plaintext failed, please check your key and IV.');
        }

        return [
            'ciphertext' => base64_encode($ciphertext.$tag),
            'iv' => base64_encode($iv),
            'associated_data' => $associatedData,
        ];
    }

    /**
     * @throws RuntimeException
     */
    public function decrypt(
        string $ciphertext,
        #[SensitiveParameter] string $key,
        string $iv,
        string $associatedData = ''
    ): string {
        $decodedCiphertext = base64_decode($ciphertext, true);
        if ($decodedCiphertext === false) {
            throw new RuntimeException('Base64 decoding failed. Invalid ciphertext.');
        }
        if (strlen($decodedCiphertext) < self::TAG_LENGTH) {
            throw new RuntimeException('Ciphertext too short, cannot extract auth tag.');
        }
        $tag = substr($decodedCiphertext, -self::TAG_LENGTH);
        $cipherData = substr($decodedCiphertext, 0, -self::TAG_LENGTH);

        $plaintext = openssl_decrypt($cipherData, static::ALGO, $key, OPENSSL_RAW_DATA, $iv, $tag, $associatedData);

        if ($plaintext === false) {
            throw new RuntimeException('Decrypting the input $ciphertext failed, please checking your $key and $iv whether or nor correct.');
        }

        return $plaintext;
    }
}
