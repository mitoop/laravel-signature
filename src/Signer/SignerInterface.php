<?php

namespace Mitoop\LaravelSignature\Signer;

use SensitiveParameter;

interface SignerInterface
{
    public function sign(string $payload, #[SensitiveParameter] string $secretKey): string;

    public function verify(string $payload, #[SensitiveParameter] string $secretKey, string $sign): bool;
}
