<?php

namespace Mitoop\LaravelSignature\Signer;

use Mitoop\LaravelSignature\Exceptions\SignErrorException;
use Mitoop\LaravelSignature\Exceptions\VerifyErrorException;
use Mitoop\LaravelSignature\Key\PrivateKey;
use Mitoop\LaravelSignature\Key\PublicKey;
use phpseclib3\Crypt\EC;
use SensitiveParameter;
use Throwable;

class Ed25519Signer extends EdDSASigner
{
    /**
     * @throws SignErrorException
     */
    public function sign(string $payload, #[SensitiveParameter] string $key): string
    {
        try {
            $privateKey = EC::loadPrivateKey((new PrivateKey($key))->getKey());

            return base64_encode($privateKey->sign($payload));
        } catch (Throwable $e) {
            throw new SignErrorException('Sign failed: '.$e->getMessage());
        }
    }

    /**
     * @throws VerifyErrorException
     */
    public function verify(string $payload, #[SensitiveParameter] string $key, string $sign): bool
    {
        $signature = base64_decode($sign, true);

        if ($signature === false) {
            return false;
        }

        try {
            $publicKey = EC::loadPublicKey((new PublicKey($key))->getKey());

            return $publicKey->verify($payload, $signature);
        } catch (Throwable $e) {
            throw new VerifyErrorException('Verify failed: '.$e->getMessage());
        }
    }
}
