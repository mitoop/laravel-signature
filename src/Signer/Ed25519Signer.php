<?php

namespace Mitoop\LaravelSignature\Signer;

use Mitoop\LaravelSignature\Exceptions\InvalidArgumentException;
use Mitoop\LaravelSignature\Key\KeyType;
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
        $rawPrivateKey = $this->extractKeyFromPem($privateKey, KeyType::PRIVATE);

        return base64_encode(sodium_crypto_sign_detached($payload, $rawPrivateKey));
    }

    /**
     * @throws SodiumException
     * @throws InvalidArgumentException
     */
    public function verify(string $payload, #[SensitiveParameter] string $key, string $sign): bool
    {
        $rawPublicKey = $this->extractKeyFromPem($key);

        $rawSignature = base64_decode($sign, true);
        if ($rawSignature === false) {
            throw new InvalidArgumentException('Invalid base64 signature');
        }

        return sodium_crypto_sign_verify_detached($rawSignature, $payload, $rawPublicKey);
    }

    /**
     * @throws InvalidArgumentException
     */
    protected function extractKeyFromPem(string $pem, KeyType $keyType = KeyType::PUBLIC): string
    {
        $type = $keyType->value;
        $pattern = sprintf(
            '/-----BEGIN %s KEY-----(.+?)-----END %s KEY-----/s',
            preg_quote($type, '/'),
            preg_quote($type, '/')
        );

        if (! preg_match($pattern, $pem, $matches)) {
            throw new InvalidArgumentException("Invalid PEM format for $type key");
        }

        $raw = base64_decode(trim($matches[1]), true);
        if ($raw === false) {
            throw new InvalidArgumentException("Cannot decode base64 content of $type key");
        }

        return substr($raw, -32);
    }
}
