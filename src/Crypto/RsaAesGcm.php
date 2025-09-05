<?php

namespace Mitoop\LaravelSignature\Crypto;

use Mitoop\LaravelSignature\Exceptions\RuntimeException;
use Random\RandomException;
use SensitiveParameter;

class RsaAesGcm
{
    public const CIPHER = 'aes-256-gcm';

    public const AES_KEY_SIZE = 32;

    /**
     * @throws RuntimeException
     * @throws RandomException
     */
    public function encrypt(
        #[SensitiveParameter]
        string $plainText,
        #[SensitiveParameter]
        string $rsaPublicKey,
        string $associatedData = ''
    ): array {
        $aesKey = random_bytes(self::AES_KEY_SIZE);

        if (! openssl_public_encrypt($aesKey, $encryptedKey, $rsaPublicKey, OPENSSL_PKCS1_OAEP_PADDING)) {
            throw new RuntimeException('RSA encrypt AES key failed. Please check the public key.');
        }

        $iv = random_bytes(openssl_cipher_iv_length(self::CIPHER));
        $tag = '';
        $cipherText = openssl_encrypt(
            $plainText,
            self::CIPHER,
            $aesKey,
            OPENSSL_RAW_DATA,
            $iv,
            $tag,
            $associatedData
        );

        if ($cipherText === false) {
            throw new RuntimeException('AES-GCM encrypt data failed.');
        }

        return [
            'encrypted_key' => base64_encode($encryptedKey),
            'iv' => base64_encode($iv),
            'tag' => base64_encode($tag),
            'cipher_text' => base64_encode($cipherText),
            'associated_data' => $associatedData,
        ];
    }

    /**
     * @throws RuntimeException
     */
    public function decrypt(
        #[SensitiveParameter]
        string $encryptedKey,
        #[SensitiveParameter]
        string $cipherText,
        #[SensitiveParameter]
        string $rsaPrivateKey,
        string $iv,
        string $tag,
        string $associatedData = ''
    ): string {
        $decodedEncryptedKey = base64_decode($encryptedKey, true);
        if ($decodedEncryptedKey === false) {
            throw new RuntimeException('Invalid base64 for encrypted_key.');
        }

        if (! openssl_private_decrypt($decodedEncryptedKey, $aesKey, $rsaPrivateKey, OPENSSL_PKCS1_OAEP_PADDING)) {
            throw new RuntimeException('RSA decrypt AES key failed. Please check the private key.');
        }

        $plainText = openssl_decrypt(
            base64_decode($cipherText),
            self::CIPHER,
            $aesKey,
            OPENSSL_RAW_DATA,
            base64_decode($iv),
            base64_decode($tag),
            $associatedData
        );

        if ($plainText === false) {
            throw new RuntimeException('AES-GCM decrypt data failed.');
        }

        return $plainText;
    }
}
