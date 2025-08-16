<?php

namespace Mitoop\LaravelSignature\Key\Generators;

interface KeyGeneratorInterface
{
    /**
     * @return string[] [$privateKey, $publicKey]
     */
    public function generate(): array;
}
