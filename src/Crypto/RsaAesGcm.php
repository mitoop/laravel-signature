<?php

namespace Mitoop\LaravelSignature\Crypto;

use Mitoop\LaravelSignature\Exceptions\RuntimeException;
use Random\RandomException;
use SensitiveParameter;

class RsaAesGcm
{
    public const ALGO = 'aes-256-gcm';

    public const AES_KEY_SIZE = 32;

    public const TAG_LENGTH = 16;

    /**
     * @throws RuntimeException
     * @throws RandomException
     */
    public function encrypt(
        #[SensitiveParameter] string $plainText,
        #[SensitiveParameter] string $rsaPublicKey,
        string $associatedData = ''
    ): array {
        $aesKey = random_bytes(self::AES_KEY_SIZE);

        if (! openssl_public_encrypt($aesKey, $encryptedKey, $rsaPublicKey, OPENSSL_PKCS1_OAEP_PADDING)) {
            throw new RuntimeException('RSA encrypt AES key failed. Please check the public key.');
        }

        $iv = random_bytes(openssl_cipher_iv_length(self::ALGO));
        $tag = '';
        $cipherText = openssl_encrypt(
            $plainText,
            self::ALGO,
            $aesKey,
            OPENSSL_RAW_DATA,
            $iv,
            $tag,
            $associatedData,
            self::TAG_LENGTH
        );

        if ($cipherText === false) {
            throw new RuntimeException('AES-GCM encrypt data failed.');
        }

        $ciphertextWithTag = base64_encode($cipherText.$tag);

        return [
            'encrypted_key' => base64_encode($encryptedKey),
            'iv' => base64_encode($iv),
            'ciphertext' => $ciphertextWithTag,
            'associated_data' => $associatedData,
        ];
    }

    /**
     * @throws RuntimeException
     */
    public function decrypt(
        #[SensitiveParameter] string $encryptedKey,
        #[SensitiveParameter] string $ciphertext,
        #[SensitiveParameter] string $rsaPrivateKey,
        string $iv,
        string $associatedData = ''
    ): string {
        $decodedEncryptedKey = base64_decode($encryptedKey, true);
        if ($decodedEncryptedKey === false) {
            throw new RuntimeException('Invalid base64 for encrypted_key.');
        }

        if (! openssl_private_decrypt($decodedEncryptedKey, $aesKey, $rsaPrivateKey, OPENSSL_PKCS1_OAEP_PADDING)) {
            throw new RuntimeException('RSA decrypt AES key failed. Please check the private key.');
        }

        $decodedCiphertext = base64_decode($ciphertext, true);
        if ($decodedCiphertext === false) {
            throw new RuntimeException('Invalid base64 for ciphertext.');
        }
        if (strlen($decodedCiphertext) < self::TAG_LENGTH) {
            throw new RuntimeException('Ciphertext too short, cannot extract auth tag.');
        }
        $tag = substr($decodedCiphertext, -self::TAG_LENGTH);
        $cipherData = substr($decodedCiphertext, 0, -self::TAG_LENGTH);
        $iv = base64_decode($iv, true);
        if ($iv === false) {
            throw new RuntimeException('Invalid base64 for iv.');
        }
        $plainText = openssl_decrypt(
            $cipherData,
            self::ALGO,
            $aesKey,
            OPENSSL_RAW_DATA,
            $iv,
            $tag,
            $associatedData
        );

        if ($plainText === false) {
            throw new RuntimeException('AES-GCM decrypt data failed.');
        }

        return $plainText;
    }
}
