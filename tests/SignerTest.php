<?php

declare(strict_types=1);

use Mitoop\LaravelSignature\Key\Generators\Ed25519KeyGenerator;
use Mitoop\LaravelSignature\Key\Generators\RsaKeyGenerator;
use Mitoop\LaravelSignature\Signer\Ed25519Signer;
use Mitoop\LaravelSignature\Signer\HmacSigner;
use Mitoop\LaravelSignature\Signer\RsaSigner;
use PHPUnit\Framework\TestCase;

final class SignerTest extends TestCase
{
    public function test_hmac_rejects_a_signature_with_a_different_length(): void
    {
        $signer = new HmacSigner;
        $signature = $signer->sign('payload', 'secret');

        $this->assertTrue($signer->verify('payload', 'secret', $signature));
        $this->assertFalse($signer->verify('payload', 'secret', 'short'));
        $this->assertFalse($signer->verify('payload', 'secret', str_repeat('A', strlen($signature))));
    }

    public function test_rsa_rejects_invalid_base64(): void
    {
        [$privateKey, $publicKey] = (new RsaKeyGenerator)->generate();
        $signer = new RsaSigner;
        $signature = $signer->sign('payload', $privateKey);

        $this->assertTrue($signer->verify('payload', $publicKey, $signature));
        $this->assertFalse($signer->verify('payload', $publicKey, '@@@'));
        $this->assertFalse($signer->verify('payload', $publicKey, 'not-the-signature'));
    }

    public function test_ed25519_rejects_invalid_base64(): void
    {
        [$privateKey, $publicKey] = (new Ed25519KeyGenerator)->generate();
        $signer = new Ed25519Signer;
        $signature = $signer->sign('payload', $privateKey);

        $this->assertTrue($signer->verify('payload', $publicKey, $signature));
        $this->assertFalse($signer->verify('payload', $publicKey, '@@@'));
    }
}
