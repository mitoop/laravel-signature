<?php

namespace Mitoop\LaravelSignature\Validation;

use Illuminate\Http\Request;
use Illuminate\Support\Facades\Cache;
use Mitoop\LaravelSignature\Exceptions\RuntimeException;
use Mitoop\LaravelSignature\Exceptions\ValidationException;
use Mitoop\LaravelSignature\Signer\SignerInterface;
use Mitoop\LaravelSignature\Signer\SignType;

class Validator
{
    protected const MAX_NONCE_LENGTH = 128;

    /**
     * @throws ValidationException
     * @throws RuntimeException
     */
    public function pass(Request $request): bool
    {
        $payload = $this->parseAuthHeader((string) $request->header('Authorization'));

        $scheme = $payload->getScheme();
        $appId = $payload->getAppId();
        $mchId = $payload->getMchId();
        $timestamp = $payload->getTimestamp();
        $nonce = $payload->getNonce();
        $sign = $payload->getSign();

        $signer = $this->getSigner($scheme);
        $application = $this->getApplication($mchId, $appId);

        $allowedIps = $application->getAllowedIps();

        if ($allowedIps && ! in_array($request->ip(), $allowedIps, true)) {
            throw new ValidationException('IP address not allowed');
        }

        if (! $signer->verify($this->stringToSign($request, $timestamp, $nonce), $application->getKey(), $sign)) {
            return false;
        }

        $currentTimestamp = time();
        $ttl = (int) config('signature.ttl');

        if (! config('signature.skip_ttl_check') && abs($currentTimestamp - $timestamp) > $ttl) {
            throw new ValidationException(sprintf(
                'Request timestamp is outside the allowed clock offset. Current timestamp: %d, provided timestamp: %d, allowed max offset: %d seconds.',
                $currentTimestamp,
                $timestamp,
                $ttl
            ));
        }

        if (! config('signature.skip_nonce_check')
            && ! Cache::add(sprintf('mitoop_signature:%s:%s', $application->getApplicationId(), $nonce), 1, $ttl)) {
            throw new ValidationException('Duplicate request detected');
        }

        app(Context::class)->set('application', $application);

        return true;
    }

    /**
     * @throws ValidationException
     */
    protected function parseAuthHeader(string $authorization): AuthPayload
    {
        if (empty($authorization)) {
            throw new ValidationException('Authorization header is required');
        }

        $parts = explode(' ', $authorization, 2);

        if (count($parts) !== 2) {
            throw new ValidationException('Invalid authorization format');
        }

        $data = ['scheme' => $parts[0]];
        $items = explode(',', $parts[1]);

        $requiredKeys = AuthorizationParameter::values();
        foreach ($items as $item) {
            $parts = explode('=', $item, 2);

            if (count($parts) !== 2) {
                throw new ValidationException('Invalid authorization format');
            }

            [$key, $value] = array_map('trim', $parts);

            if (in_array($key, $requiredKeys, true)) {
                $value = trim($value, '"');
                if ($value === '') {
                    throw new ValidationException("{$key} cannot be empty");
                }
                if ($key === AuthorizationParameter::NONCE->value && strlen($value) > self::MAX_NONCE_LENGTH) {
                    throw new ValidationException('nonce is too long');
                }
                if ($key === AuthorizationParameter::TIMESTAMP->value && ! ctype_digit($value)) {
                    throw new ValidationException('timestamp must be a unix timestamp');
                }
                $data[$key] = $value;
            }
        }

        $this->validateRequiredKeys($data);

        return new AuthPayload($data);
    }

    /**
     * @throws ValidationException
     */
    protected function validateRequiredKeys(array $data): void
    {
        $requiredKeys = AuthorizationParameter::values();

        foreach ($requiredKeys as $key) {
            if (! isset($data[$key])) {
                throw new ValidationException("Missing {$key}");
            }
        }
    }

    /**
     * @throws ValidationException
     * @throws RuntimeException
     */
    protected function getApplication(string $mchId, string $appId): ApplicationInterface
    {
        if (! app()->bound(ApplicationResolverInterface::class)) {
            throw new RuntimeException('Application resolver is not bound');
        }

        $application = app(ApplicationResolverInterface::class)->resolve($mchId, $appId);

        if (! $application) {
            throw new ValidationException('Invalid merchant ID or application ID');
        }

        return $application;
    }

    protected function stringToSign(Request $request, $timestamp, $nonce): string
    {
        return strtoupper($request->method())."\n".
            $request->getRequestUri()."\n".
            $timestamp."\n".
            $nonce."\n".
            $request->getContent()."\n";
    }

    /**
     * @throws ValidationException
     */
    protected function getSigner(string $scheme): SignerInterface
    {
        [$prefix, $signTypeStr] = array_pad(explode('-', $scheme, 2), 2, null);

        $prefix = strtoupper((string) $prefix);
        $signTypeStr = (string) $signTypeStr;
        $configPrefix = strtoupper(config('signature.prefix'));

        if ($prefix === '' || $signTypeStr === '') {
            throw new ValidationException("Invalid auth type format: '{$scheme}'");
        }

        if ($prefix !== $configPrefix) {
            throw new ValidationException("Prefix mismatch: '{$prefix}'");
        }

        if (! $signType = SignType::tryFrom($signTypeStr)) {
            throw new ValidationException("Unsupported sign type: '{$signTypeStr}'");
        }

        return $signType->signer();
    }
}
