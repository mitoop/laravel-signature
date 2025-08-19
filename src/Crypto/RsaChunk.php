<?php

namespace Mitoop\LaravelSignature\Crypto;

use Mitoop\LaravelSignature\Exceptions\RuntimeException;
use SensitiveParameter;

class RsaChunk
{
    /**
     * @throws RuntimeException
     */
    public function encrypt(string $plaintext, #[SensitiveParameter] string $secretKey): string
    {
        $key = $this->getKey($secretKey, true);
        $info = $this->getKeyDetails($key);

        $paddingLength = 42; // 适用于 OPENSSL_PKCS1_OAEP_PADDING, OPENSSL_PKCS1_PADDING 为 11
        $maxChunkSize = ($info['bits'] / 8) - $paddingLength;

        $chunks = str_split($plaintext, $maxChunkSize);
        $encryptedChunks = array_map(fn ($chunk) => $this->encryptChunk($chunk, $key), $chunks);

        return base64_encode(implode('', $encryptedChunks));
    }

    /**
     * @throws RuntimeException
     */
    public function decrypt(string $cipherText, #[SensitiveParameter] string $secretKey): string
    {
        $cipherText = base64_decode($cipherText) ?: throw new RuntimeException('Base64 decoding failed. Invalid ciphertext.');

        $key = $this->getKey($secretKey, false);
        $info = $this->getKeyDetails($key);

        $blockSize = $info['bits'] / 8;
        $chunks = str_split($cipherText, $blockSize);
        $decryptedChunks = array_map(fn ($chunk) => $this->decryptChunk($chunk, $key), $chunks);

        return implode('', $decryptedChunks);
    }

    /**
     * @throws RuntimeException
     */
    protected function getKey(string $key, bool $isPublic)
    {
        $opensslFunc = $isPublic ? 'openssl_pkey_get_public' : 'openssl_pkey_get_private';

        return $opensslFunc($key) ?: throw new RuntimeException('Invalid '.($isPublic ? 'public' : 'private').' key: '.(openssl_error_string() ?: 'Unknown error.'));
    }

    /**
     * @throws RuntimeException
     */
    protected function getKeyDetails($key): array
    {
        $info = openssl_pkey_get_details($key);

        return $info && isset($info['bits']) ? $info : throw new RuntimeException('Failed to retrieve key details: '.(openssl_error_string() ?: 'Unknown error.'));
    }

    /**
     * @throws RuntimeException
     */
    protected function encryptChunk(string $chunk, $key): string
    {
        return openssl_public_encrypt($chunk, $encrypted, $key, OPENSSL_PKCS1_OAEP_PADDING)
            ? $encrypted
            : throw new RuntimeException('Encryption failed: '.(openssl_error_string() ?: 'Unknown error.'));
    }

    /**
     * @throws RuntimeException
     */
    protected function decryptChunk(string $chunk, $key): string
    {
        return openssl_private_decrypt($chunk, $decrypted, $key, OPENSSL_PKCS1_OAEP_PADDING)
            ? $decrypted
            : throw new RuntimeException('Decryption failed: '.(openssl_error_string() ?: 'Unknown error.'));
    }
}
