<?php

namespace Mitoop\LaravelSignature\Key;

enum KeyAlgo: string
{
    case RSA = 'rsa';
    case ED25519 = 'ed25519';
}
