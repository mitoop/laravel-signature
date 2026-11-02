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
        $prefix = ucfirst(strtolower(config('signature.prefix')));

        $prefixedHeaders = [];
        foreach ($headers as $k => $v) {
            $prefixedHeaders["{$prefix}-{$k}"] = $v;
        }

        return array_merge($prefixedHeaders, [
            "{$prefix}-Nonce" => $nonce,
            "{$prefix}-Signature" => $sign,
            "{$prefix}-Signature-Type" => strtoupper(sprintf('%s-%s', $prefix, $this->signType->value)),
            "{$prefix}-Timestamp" => $timestamp,
        ]);
    }

    protected function createPayload(array $params, string $timestamp, string $nonce, int $jsonOptions): string
    {
        return $timestamp."\n".
            $nonce."\n".
            json_encode($params, $jsonOptions)."\n";
    }
}
