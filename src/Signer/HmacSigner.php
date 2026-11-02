<?php

namespace Mitoop\LaravelSignature\Signer;

use SensitiveParameter;

class HmacSigner implements SignerInterface
{
    public function sign(string $payload, #[SensitiveParameter] string $key): string
    {
        return base64_encode(hash_hmac('sha256', $payload, $key, true));
    }

    public function verify(string $payload, #[SensitiveParameter] string $key, string $sign): bool
    {
        $expected = $this->sign($payload, $key);

        if (strlen($expected) !== strlen($sign)) {
            return false;
        }

        return hash_equals($expected, $sign);
    }
}
