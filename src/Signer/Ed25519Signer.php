<?php

namespace Mitoop\LaravelSignature\Signer;

use Mitoop\LaravelSignature\Exceptions\InvalidArgumentException;
use phpseclib3\Crypt\EC;
use SensitiveParameter;

class Ed25519Signer extends EdDSASigner
{
    public function sign(string $payload, #[SensitiveParameter] string $privateKey): string
    {
        $privateKey = EC::loadPrivateKey($privateKey);

        return base64_encode($privateKey->sign($payload));
    }

    /**
     * @throws InvalidArgumentException
     */
    public function verify(string $payload, #[SensitiveParameter] string $key, string $sign): bool
    {
        $publicKey = EC::loadPublicKey($key);
        $signature = base64_decode($sign, true);

        if ($signature === false) {
            throw new InvalidArgumentException('Invalid base64 signature');
        }

        return $publicKey->verify($payload, $signature);
    }
}
