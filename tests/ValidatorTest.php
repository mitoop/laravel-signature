<?php

declare(strict_types=1);

require_once __DIR__.'/PackageTestCase.php';

use Illuminate\Http\Request;
use Illuminate\Testing\TestResponse;
use Mitoop\LaravelSignature\Exceptions\ValidationException;
use Mitoop\LaravelSignature\Middlewares\ValidateSignature;
use Mitoop\LaravelSignature\Signer\HmacSigner;
use Mitoop\LaravelSignature\Validation\ApplicationInterface;
use Mitoop\LaravelSignature\Validation\ApplicationResolverInterface;
use Mitoop\LaravelSignature\Validation\Context;
use Mitoop\LaravelSignature\Validation\Validator;

final class ValidatorTest extends PackageTestCase
{
    private const SECRET = 'test-secret';

    public function test_valid_signature_passes_and_stores_the_application(): void
    {
        $this->resolveApplication();
        $request = $this->signedRequest('nonce-valid');

        $this->assertTrue($this->app->make(Validator::class)->pass($request));
        $this->assertSame('app-1', $this->app->make(Context::class)->get('application')->getApplicationId());
    }

    public function test_invalid_signature_does_not_consume_the_nonce(): void
    {
        $this->resolveApplication();
        $nonce = 'nonce-retry';
        $invalid = $this->signedRequest($nonce);
        $invalid->headers->set('Authorization', str_replace(
            'sign="',
            'sign="broken',
            (string) $invalid->headers->get('Authorization'),
        ));
        $this->app->instance('request', $invalid);

        $this->assertFalse($this->app->make(Validator::class)->pass($invalid));
        $this->assertTrue($this->app->make(Validator::class)->pass($this->signedRequest($nonce)));
    }

    public function test_a_short_hmac_signature_is_rejected_as_an_invalid_signature(): void
    {
        $this->resolveApplication();

        $response = $this->throughMiddleware($this->signedRequest('nonce-short', sign: 'short'));

        $response->assertOk();
        $response->assertJsonPath('code', 401);
        $response->assertJsonPath('message', 'Invalid signature');
    }

    public function test_replay_is_rejected_after_a_valid_signature(): void
    {
        $this->resolveApplication();
        $nonce = 'nonce-replay';

        $this->assertTrue($this->app->make(Validator::class)->pass($this->signedRequest($nonce)));

        $this->expectException(ValidationException::class);
        $this->expectExceptionMessage('Duplicate request detected');

        $this->app->make(Validator::class)->pass($this->signedRequest($nonce));
    }

    public function test_clock_offset_allows_a_small_future_timestamp_and_rejects_a_large_one(): void
    {
        $this->resolveApplication();

        $this->assertTrue($this->app->make(Validator::class)->pass($this->signedRequest('nonce-soon', time() + 10)));

        $this->expectException(ValidationException::class);
        $this->expectExceptionMessage('outside the allowed clock offset');

        $this->app->make(Validator::class)->pass($this->signedRequest('nonce-far', time() + 301));
    }

    public function test_clock_failure_does_not_consume_the_nonce(): void
    {
        $this->resolveApplication();
        $nonce = 'nonce-clock';

        try {
            $this->app->make(Validator::class)->pass($this->signedRequest($nonce, time() + 301));
            $this->fail('A timestamp outside the clock offset should be rejected.');
        } catch (ValidationException $exception) {
            $this->assertStringContainsString('outside the allowed clock offset', $exception->getMessage());
        }

        $this->assertTrue($this->app->make(Validator::class)->pass($this->signedRequest($nonce)));
    }

    public function test_disallowed_ip_is_rejected(): void
    {
        $this->resolveApplication(['10.0.0.8']);
        $request = $this->signedRequest('nonce-ip');

        $this->expectException(ValidationException::class);
        $this->expectExceptionMessage('IP address not allowed');
        $this->app->make(Validator::class)->pass($request);
    }

    public function test_brand_mismatch_is_rejected_before_the_application_is_resolved(): void
    {
        $this->app->bind(ApplicationResolverInterface::class, fn () => new class implements ApplicationResolverInterface
        {
            public function resolve(string $mchId, string $appId): ?ApplicationInterface
            {
                throw new RuntimeException('resolver should not be called');
            }
        });
        $request = $this->signedRequest('nonce-brand', type: 'OTHER-SHA256-HMAC');

        $this->expectException(ValidationException::class);
        $this->expectExceptionMessage("Brand mismatch: 'OTHER'");

        $this->app->make(Validator::class)->pass($request);
    }

    public function test_missing_authorization_header_is_rejected(): void
    {
        $request = Request::create('/api/data/cities', 'POST', content: '{}');
        $this->app->instance('request', $request);

        $this->expectException(ValidationException::class);
        $this->expectExceptionMessage('Authorization header is required');

        $this->app->make(Validator::class)->pass($request);
    }

    public function test_nonce_longer_than_128_characters_is_rejected(): void
    {
        $this->resolveApplication();

        $this->expectException(ValidationException::class);
        $this->expectExceptionMessage('nonce is too long');

        $this->app->make(Validator::class)->pass($this->signedRequest(str_repeat('a', 129)));
    }

    public function test_middleware_returns_the_next_response_after_a_valid_signature(): void
    {
        $this->resolveApplication();

        $response = $this->throughMiddleware($this->signedRequest('nonce-next'));

        $response->assertOk();
        $response->assertJsonPath('ok', true);
    }

    /**
     * @param  list<string>|null  $allowedIps
     */
    private function resolveApplication(?array $allowedIps = null): void
    {
        $application = new class(self::SECRET, $allowedIps) implements ApplicationInterface
        {
            public function __construct(private string $secret, private ?array $allowedIps) {}

            public function getAllowedIps(): ?array
            {
                return $this->allowedIps;
            }

            public function getSecretKey(): string
            {
                return $this->secret;
            }

            public function getApplicationId(): string
            {
                return 'app-1';
            }
        };

        $this->app->bind(ApplicationResolverInterface::class, fn () => new class($application) implements ApplicationResolverInterface
        {
            public function __construct(private ApplicationInterface $application) {}

            public function resolve(string $mchId, string $appId): ?ApplicationInterface
            {
                return $this->application;
            }
        });
    }

    private function signedRequest(string $nonce, ?int $timestamp = null, string $type = 'YOUR_BRAND-SHA256-HMAC', ?string $sign = null): Request
    {
        $timestamp ??= time();
        $body = '{"name":"x"}';
        $request = Request::create('/api/data/cities', 'POST', server: ['REMOTE_ADDR' => '127.0.0.1'], content: $body);
        $payload = strtoupper($request->method())."\n".
            $request->getRequestUri()."\n".
            $timestamp."\n".
            $nonce."\n".
            $request->getContent()."\n";
        $sign ??= (new HmacSigner)->sign($payload, self::SECRET);
        $request->headers->set('Authorization', sprintf(
            '%s mchid="mch-1",appid="app-1",nonce="%s",timestamp="%d",sign="%s"',
            $type,
            $nonce,
            $timestamp,
            $sign,
        ));
        $this->app->instance('request', $request);

        return $request;
    }

    private function throughMiddleware(Request $request): TestResponse
    {
        $this->app->instance('request', $request);

        return TestResponse::fromBaseResponse(
            (new ValidateSignature)->handle($request, fn () => response()->json(['ok' => true]))
        );
    }
}
