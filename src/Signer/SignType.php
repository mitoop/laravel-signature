<?php

namespace Mitoop\LaravelSignature\Signer;

use ArchTech\Enums\InvokableCases;

enum SignType: string
{
    use InvokableCases;

    case SHA256_RSA2048 = 'SHA256-RSA2048';

    case SHA256_HMAC = 'SHA256-HMAC';

    case ED25519 = 'ED25519';

    public function signer(): SignerInterface
    {
        return match ($this) {
            self::SHA256_RSA2048 => new RsaSigner,
            self::SHA256_HMAC => new HmacSigner,
            self::ED25519 => new Ed25519Signer,
        };
    }
}
