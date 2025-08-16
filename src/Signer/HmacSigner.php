<?php

namespace Mitoop\LaravelSignature\Signer;

use SensitiveParameter;

class HmacSigner implements SignerInterface
{
    public function sign(string $payload, #[SensitiveParameter] string $privateKey): string
    {
        return base64_encode(hash_hmac('sha256', $payload, $privateKey, true));
    }

    public function verify(string $payload, #[SensitiveParameter] string $key, string $sign): bool
    {
        return hash_equals($this->sign($payload, $key), $sign);
    }
}
