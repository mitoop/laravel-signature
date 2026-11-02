<?php

declare(strict_types=1);

require_once __DIR__.'/PackageTestCase.php';

use Illuminate\Support\Facades\Http;
use Mitoop\LaravelSignature\Http\Client;
use Mitoop\LaravelSignature\Key\Generators\RsaKeyGenerator;
use Mitoop\LaravelSignature\Signer\HmacSigner;
use Mitoop\LaravelSignature\Signer\RsaSigner;
use Mitoop\LaravelSignature\Signer\SignType;

final class ClientTest extends PackageTestCase
{
    public function test_callback_signature_covers_the_json_body_that_is_sent(): void
    {
        Http::fake(['https://outer-service.test/*' => Http::response('success')]);
        $params = ['order_id' => '123456', 'status' => 'success'];

        $response = $this->app->make(Client::class)
            ->useSigner(SignType::SHA256_HMAC)
            ->post('https://outer-service.test/notify', $params, 'platform-private-key');

        $this->assertTrue($response->ok());
        Http::assertSent(function ($request) use ($params) {
            $body = $request->body();
            $timestamp = $request->header('Your_app-Timestamp')[0];
            $nonce = $request->header('Your_app-Nonce')[0];
            $signature = $request->header('Your_app-Signature')[0];

            return $body === json_encode($params)
                && $request->header('Your_app-Signature-Type')[0] === 'YOUR_APP-SHA256-HMAC'
                && (new HmacSigner)->verify($timestamp."\n".$nonce."\n".$body."\n", 'platform-private-key', $signature);
        });
    }

    public function test_changing_the_signer_does_not_affect_the_next_client(): void
    {
        Http::fake(['https://outer-service.test/*' => Http::response('success')]);
        [$privateKey, $publicKey] = (new RsaKeyGenerator)->generate();

        $this->app->make(Client::class)
            ->useSigner(SignType::SHA256_HMAC)
            ->post('https://outer-service.test/hmac', ['ok' => true], 'secret');
        $this->app->make(Client::class)
            ->post('https://outer-service.test/rsa', ['ok' => true], $privateKey);

        Http::assertSent(function ($request) {
            return $request->url() === 'https://outer-service.test/hmac'
                && $request->header('Your_app-Signature-Type')[0] === 'YOUR_APP-SHA256-HMAC';
        });
        Http::assertSent(function ($request) use ($publicKey) {
            if ($request->url() !== 'https://outer-service.test/rsa') {
                return false;
            }

            $body = $request->body();
            $timestamp = $request->header('Your_app-Timestamp')[0];
            $nonce = $request->header('Your_app-Nonce')[0];

            return $request->header('Your_app-Signature-Type')[0] === 'YOUR_APP-SHA256-RSA2048'
                && (new RsaSigner)->verify(
                    $timestamp."\n".$nonce."\n".$body."\n",
                    $publicKey,
                    $request->header('Your_app-Signature')[0],
                );
        });
    }
}
