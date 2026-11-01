<?php

declare(strict_types=1);

use Mitoop\LaravelSignature\Crypto\AesGcm;
use Mitoop\LaravelSignature\Crypto\Rsa;
use Mitoop\LaravelSignature\Crypto\RsaAesGcm;
use Mitoop\LaravelSignature\Exceptions\RuntimeException;
use Mitoop\LaravelSignature\Key\Generators\RsaKeyGenerator;
use PHPUnit\Framework\TestCase;

final class CryptoTest extends TestCase
{
    public function test_aes_gcm_decrypts_the_base64_iv_returned_by_encrypt(): void
    {
        $aes = new AesGcm;
        $key = random_bytes(32);
        $encrypted = $aes->encrypt('hello', $key, 'aad');

        $this->assertSame('hello', $aes->decrypt(
            $encrypted['ciphertext'],
            $key,
            $encrypted['iv'],
            $encrypted['associated_data'],
        ));
    }

    public function test_aes_gcm_rejects_a_raw_iv(): void
    {
        $aes = new AesGcm;
        $key = random_bytes(32);
        $encrypted = $aes->encrypt('hello', $key);

        $this->expectException(RuntimeException::class);

        $aes->decrypt($encrypted['ciphertext'], $key, random_bytes(12));
    }

    public function test_rsa_round_trip(): void
    {
        [$privateKey, $publicKey] = (new RsaKeyGenerator)->generate();
        $rsa = new Rsa;

        $this->assertSame('hello', $rsa->decrypt($rsa->encrypt('hello', $publicKey), $privateKey));
    }

    public function test_rsa_aes_gcm_round_trip(): void
    {
        [$privateKey, $publicKey] = (new RsaKeyGenerator)->generate();
        $cipher = new RsaAesGcm;
        $encrypted = $cipher->encrypt('hello', $publicKey, 'aad');

        $this->assertSame('hello', $cipher->decrypt(
            $encrypted['encrypted_key'],
            $encrypted['ciphertext'],
            $privateKey,
            $encrypted['iv'],
            $encrypted['associated_data'],
        ));
    }
}
