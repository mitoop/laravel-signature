<?php

namespace Mitoop\LaravelSignature\Validation;

class AuthPayload
{
    public function __construct(protected array $data) {}

    public function getScheme(): string
    {
        return (string) $this->data[AuthorizationParameter::SCHEME()];
    }

    public function getMchId(): string
    {
        return (string) $this->data[AuthorizationParameter::MCH_ID()];
    }

    public function getAppId(): string
    {
        return (string) $this->data[AuthorizationParameter::APP_ID()];
    }

    public function getNonce(): string
    {
        return (string) $this->data[AuthorizationParameter::NONCE()];
    }

    public function getSign(): string
    {
        return (string) $this->data[AuthorizationParameter::SIGN()];
    }

    public function getTimestamp(): int
    {
        return (int) $this->data[AuthorizationParameter::TIMESTAMP()];
    }
}
