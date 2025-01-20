<?php

namespace Mitoop\LaravelSignature\Signer;

use Mitoop\LaravelSignature\Exceptions\InvalidArgumentException;
use Mitoop\LaravelSignature\Exceptions\UnexpectedValueException;
use Mitoop\LaravelSignature\Key\PrivateKey;
use Mitoop\LaravelSignature\Key\PublicKey;
use SensitiveParameter;

class RsaSigner implements SignerInterface
{
    /**
     * @throws UnexpectedValueException
     * @throws InvalidArgumentException
     */
    public function sign(string $payload, #[SensitiveParameter] string $secretKey): string
    {
        if (openssl_sign($payload, $sign, (new PrivateKey($secretKey))->getKey(), OPENSSL_ALGO_SHA256)) {
            return base64_encode($sign);
        }

        throw new UnexpectedValueException('Signing failed. Please check if the provided private key is correct.');
    }

    public function verify(string $payload, #[SensitiveParameter] string $secretKey, string $sign): bool
    {
        return openssl_verify(
            $payload,
            base64_decode($sign),
            (new PublicKey($secretKey))->getKey(),
            OPENSSL_ALGO_SHA256) === 1;
    }
}
