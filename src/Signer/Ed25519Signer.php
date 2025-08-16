<?php

namespace Mitoop\LaravelSignature\Signer;

use Mitoop\LaravelSignature\Exceptions\InvalidArgumentException;
use SensitiveParameter;
use SodiumException;

class Ed25519Signer extends EdDSASigner
{
    /**
     * @throws SodiumException
     * @throws InvalidArgumentException
     */
    public function sign(string $payload, #[SensitiveParameter] string $privateKey): string
    {
        $rawSecretKey = base64_decode($privateKey, true);

        if ($rawSecretKey === false) {
            throw new InvalidArgumentException('Invalid base64 secret key');
        }

        return base64_encode(sodium_crypto_sign_detached($payload, $rawSecretKey));
    }

    /**
     * @throws SodiumException
     * @throws InvalidArgumentException
     */
    public function verify(string $payload, #[SensitiveParameter] string $key, string $sign): bool
    {
        $rawPublicKey = base64_decode($key, true);
        if ($rawPublicKey === false) {
            throw new InvalidArgumentException('Invalid base64 public key');
        }

        $rawSignature = base64_decode($sign, true);
        if ($rawSignature === false) {
            throw new InvalidArgumentException('Invalid base64 signature');
        }

        return sodium_crypto_sign_verify_detached($rawSignature, $payload, $rawPublicKey);
    }
}
