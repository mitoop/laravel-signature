<?php

namespace Mitoop\LaravelSignature\Signer;

use Mitoop\LaravelSignature\Exceptions\SignErrorException;
use Mitoop\LaravelSignature\Key\PrivateKey;
use Mitoop\LaravelSignature\Key\PublicKey;
use SensitiveParameter;

class RsaSigner implements SignerInterface
{
    /**
     * @throws SignErrorException
     */
    public function sign(string $payload, #[SensitiveParameter] string $privateKey): string
    {
        if (openssl_sign($payload, $sign, (new PrivateKey($privateKey))->getKey(), OPENSSL_ALGO_SHA256)) {
            return base64_encode($sign);
        }

        throw new SignErrorException('Sign Error');
    }

    public function verify(string $payload, #[SensitiveParameter] string $key, string $sign): bool
    {
        return openssl_verify(
            $payload,
            base64_decode($sign),
            (new PublicKey($key))->getKey(),
            OPENSSL_ALGO_SHA256) === 1;
    }
}
