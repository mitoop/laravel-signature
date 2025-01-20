<?php

namespace Mitoop\LaravelSignature\Http;

use Illuminate\Http\Client\Response as IlluminateResponse;

/**
 * @method string body()
 * @method int status()
 */
class Response
{
    public function __construct(protected IlluminateResponse $response) {}

    public function ok(): bool
    {
        return $this->response->ok() && $this->response->body() === 'success';
    }

    public function __call($method, $parameters): mixed
    {
        return $this->response->$method(...$parameters);
    }
}
