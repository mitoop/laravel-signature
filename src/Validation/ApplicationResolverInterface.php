<?php

namespace Mitoop\LaravelSignature\Validation;

interface ApplicationResolverInterface
{
    public function resolve(string $mchId, string $appId): ?ApplicationInterface;
}
