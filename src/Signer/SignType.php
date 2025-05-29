<?php

namespace Mitoop\LaravelSignature\Signer;

use ArchTech\Enums\InvokableCases;

enum SignType: string
{
    use InvokableCases;

    case SHA256_RSA2048 = 'SHA256-RSA2048';

    case SHA256_HMAC = 'SHA256-HMAC';

    public function formatWithBrand(): string
    {
        return strtoupper(config('signature.brand')).'-'.$this->value;
    }

    public static function map(): array
    {
        return [
            self::SHA256_RSA2048->formatWithBrand() => RsaSigner::class,
            self::SHA256_HMAC->formatWithBrand() => HmacSigner::class,
        ];
    }
}
