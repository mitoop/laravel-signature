<?php

namespace Mitoop\LaravelSignature\Validation;

interface ApplicationInterface
{
    public function getAllowedIps(): ?array;

    public function getKey(): string;

    public function getApplicationId(): string|int;
}
