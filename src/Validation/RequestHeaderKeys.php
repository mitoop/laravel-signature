<?php

namespace Mitoop\LaravelSignature\Validation;

use ArchTech\Enums\InvokableCases;
use ArchTech\Enums\Values;

/**
 * @method static string TYPE()
 * @method static string MCH_ID()
 * @method static string APP_ID()
 * @method static string NONCE()
 * @method static string SIGN()
 * @method static string TIMESTAMP()
 */
enum RequestHeaderKeys: string
{
    use InvokableCases;
    use Values;

    case TYPE = 'type';
    case MCH_ID = 'mchid';
    case APP_ID = 'appid';
    case NONCE = 'nonce';
    case SIGN = 'sign';
    case TIMESTAMP = 'timestamp';
}
