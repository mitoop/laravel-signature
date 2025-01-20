<?php

namespace Mitoop\LaravelSignature\Signer;

use SensitiveParameter;

class HmacSigner implements SignerInterface
{
    public function verify(string $payload, #[SensitiveParameter] string $secretKey, string $sign): bool
    {
        return hash_equals($this->sign($payload, $secretKey), $sign);
    }

    public function sign(string $payload, #[SensitiveParameter] string $secretKey): string
    {
        return hash_hmac('sha256', $payload, $secretKey);
    }
}
