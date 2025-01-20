<?php

namespace Mitoop\LaravelSignature\Validation;

class AuthPayload
{
    public function __construct(protected array $data) {}

    public function getType(): string
    {
        return (string) $this->data[RequestHeaderKeys::TYPE()];
    }

    public function getMchId(): string
    {
        return (string) $this->data[RequestHeaderKeys::MCH_ID()];
    }

    public function getAppId(): string
    {
        return (string) $this->data[RequestHeaderKeys::APP_ID()];
    }

    public function getNonce(): string
    {
        return (string) $this->data[RequestHeaderKeys::NONCE()];
    }

    public function getSign(): string
    {
        return (string) $this->data[RequestHeaderKeys::SIGN()];
    }

    public function getTimestamp(): int
    {
        return (int) $this->data[RequestHeaderKeys::TIMESTAMP()];
    }
}
