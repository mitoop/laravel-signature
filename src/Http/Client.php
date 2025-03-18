<?php

namespace Mitoop\LaravelSignature\Http;

use GuzzleHttp\Psr7\Response as GuzzleResponse;
use Illuminate\Http\Client\ConnectionException;
use Illuminate\Http\Client\PendingRequest;
use Illuminate\Http\Client\Response as IlluminateResponse;
use Illuminate\Support\Facades\Http;
use Illuminate\Support\Str;
use Mitoop\LaravelSignature\Exceptions\InvalidArgumentException;
use Mitoop\LaravelSignature\Signer\SignerInterface;

class Client
{
    protected string $signType;

    public function __construct(protected array $signers) {}

    public function useSigner(string $signType): static
    {
        $this->signType = $signType;

        return $this;
    }

    /**
     * @throws InvalidArgumentException
     */
    public function post(string $url, array $params, $privateKey, array $headers = []): Response
    {
        $http = $this->getHttpClient();

        $timestamp = time();
        $nonce = str_replace('-', '', Str::orderedUuid());
        $sign = $this->getSigner($this->signType)->sign(
            $this->createPayload($params, $timestamp, $nonce),
            $privateKey
        );

        $brand = ucfirst(strtolower(config('signature.brand')));

        $http->withHeaders(array_merge([
            "{$brand}-Nonce" => $nonce,
            "{$brand}-Signature" => $sign,
            "{$brand}-Timestamp" => $timestamp,
            "{$brand}-Signature-Type" => $this->signType,
        ], $headers));

        try {
            $response = $http->post($url, $params);
        } catch (ConnectionException $e) {
            $response = new IlluminateResponse(new GuzzleResponse(500, body: 'ConnectionException:'.$e->getMessage()));
        }

        return $this->newResponse($response);
    }

    protected function getHttpClient(): PendingRequest
    {
        $brand = strtolower(config('signature.brand'));

        return Http::withHeaders(['User-Agent' => "{$brand}/1.0"])
            ->timeout(config('signature.http_timeout', 60))
            ->accept('text/plain');
    }

    protected function createPayload(array $params, $timestamp, $nonce): string
    {
        return $timestamp."\n".
            $nonce."\n".
            json_encode($params)."\n";
    }

    /**
     * @throws InvalidArgumentException
     */
    protected function getSigner(string $type): SignerInterface
    {
        if (isset($this->signers[$type])) {
            return new $this->signers[$type];
        }

        throw new InvalidArgumentException(sprintf('签名类型 %s 错误', $type));
    }

    protected function newResponse(IlluminateResponse $response): Response
    {
        return new Response($response);
    }
}
