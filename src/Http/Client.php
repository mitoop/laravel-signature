<?php

namespace Mitoop\LaravelSignature\Http;

use GuzzleHttp\Psr7\Response as GuzzleResponse;
use Illuminate\Http\Client\ConnectionException;
use Illuminate\Http\Client\PendingRequest;
use Illuminate\Http\Client\Response as IlluminateResponse;
use Illuminate\Support\Facades\Http;
use Mitoop\LaravelSignature\Signer\SignHeaderBuilder;
use Mitoop\LaravelSignature\Signer\SignType;

class Client
{
    public function __construct(protected SignHeaderBuilder $signHeaderBuilder) {}

    public function useSigner(SignType $signType): static
    {
        $this->signHeaderBuilder->useSigner($signType);

        return $this;
    }

    public function post(string $url, array $params, $privateKey, array $headers = []): Response
    {
        $http = $this->getHttpClient();

        $http->withHeaders($this->signHeaderBuilder->generate($params, $privateKey, headers: $headers));

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

    protected function newResponse(IlluminateResponse $response): Response
    {
        return new Response($response);
    }
}
