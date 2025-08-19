<?php

namespace Mitoop\LaravelSignature\Signer;

use Illuminate\Support\Str;

class SignHeaderBuilder
{
    protected SignType $signType = SignType::SHA256_RSA2048;

    public function useSigner(SignType $signType): static
    {
        $this->signType = $signType;

        return $this;
    }

    public function generate(array $params, string $key, int $jsonOptions = 0, array $headers = []): array
    {
        $timestamp = (string) time();
        $nonce = str_replace('-', '', (string) Str::orderedUuid());
        $sign = $this->signType->signer()->sign($this->createPayload($params, $timestamp, $nonce, $jsonOptions), $key);
        $brand = ucfirst(strtolower(config('signature.brand')));

        return array_merge($headers, [
            "{$brand}-Nonce" => $nonce,
            "{$brand}-Signature" => $sign,
            "{$brand}-Signature-Type" => $this->signType,
            "{$brand}-Timestamp" => $timestamp,
        ]);
    }

    protected function createPayload(array $params, string $timestamp, string $nonce, int $jsonOptions): string
    {
        return $timestamp."\n".
            $nonce."\n".
            json_encode($params, $jsonOptions)."\n";
    }
}
