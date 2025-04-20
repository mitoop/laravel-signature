<?php

namespace Mitoop\LaravelSignature\Validation;

interface ApplicationInterface
{
    public function getAllowedIps(): ?array;

    public function getSecretKey(): string;

    public function getApplicationId(): string|int;
}
