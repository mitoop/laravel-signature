<?php

namespace Mitoop\LaravelSignature\Signer;

use ArchTech\Enums\InvokableCases;

/**
 * @method static string RSA2048_SHA256()
 * @method static string HMAC_SHA256()
 */
enum SignType: string
{
    use InvokableCases;

    case RSA2048_SHA256 = 'RSA2048-SHA256';

    case HMAC_SHA256 = 'HMAC-SHA256';

    public function formatWithBrand(): string
    {
        return strtoupper(config('signature.brand')).'-'.$this->value;
    }

    public static function map(): array
    {
        return [
            self::RSA2048_SHA256->formatWithBrand() => RsaSigner::class,
            self::HMAC_SHA256->formatWithBrand() => HmacSigner::class,
        ];
    }
}
