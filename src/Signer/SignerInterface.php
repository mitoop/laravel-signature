<?php

namespace Mitoop\LaravelSignature\Signer;

use SensitiveParameter;

interface SignerInterface
{
    public function sign(string $payload, #[SensitiveParameter] string $privateKey): string;

    public function verify(string $payload, #[SensitiveParameter] string $key, string $sign): bool;
}
