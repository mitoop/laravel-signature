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
    /**
     * @throws ValidationException
     * @throws RuntimeException
     */
    public function pass(Request $request): bool
    {
        $payload = $this->parseAuthHeader((string) $request->header('Authorization'));

        $type = $payload->getType();
        $appId = $payload->getAppId();
        $mchId = $payload->getMchId();
        $timestamp = $payload->getTimestamp();
        $nonce = $payload->getNonce();
        $sign = $payload->getSign();

        $currentTimestamp = time();

        if ($timestamp > $currentTimestamp) {
            throw new ValidationException('Request timestamp cannot be in the future');
        }

        $maxOffset = config('signature.max_clock_offset');
        if (! config('signature.skip_clock_check') && $currentTimestamp - $timestamp > $maxOffset) {
            throw new ValidationException(sprintf(
                'Request timestamp is too old. Current timestamp: %d, provided timestamp: %d, allowed max offset: %d seconds.',
                $currentTimestamp,
                $timestamp,
                $maxOffset
            ));
        }

        $application = $this->getApplication($mchId, $appId);

        $allowedIps = $application->getAllowedIps();

        if ($allowedIps && ! in_array($request->ip(), $allowedIps, true)) {
            throw new ValidationException('IP address not allowed');
        }

        if (! config('signature.skip_nonce_check')
            && ! Cache::add(sprintf('mitoop_signature:%s:%s', $application->getApplicationId(), $nonce), 1, config('signature.max_clock_offset'))) {
            throw new ValidationException('Duplicate request detected');
        }

        $signer = $this->getSigner($type);

        if ($signer->verify($this->createPayload($request, $timestamp, $nonce), $application->getSecretKey(), $sign)) {
            app(Context::class)->set('application', $application);

            return true;
        }

        return false;
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

        $data = ['type' => $parts[0]];
        $items = explode(',', $parts[1]);

        $requiredKeys = RequestHeaderKeys::values();
        foreach ($items as $item) {
            $parts = explode('=', $item, 2);

            if (count($parts) !== 2) {
                throw new ValidationException('Invalid authorization format');
            }

            [$key, $value] = array_map('trim', $parts);

            if (in_array($key, $requiredKeys, true)) {
                $value = trim($value, '"');
                if (empty($value)) {
                    throw new ValidationException("{$key} cannot be empty");
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
        $requiredKeys = RequestHeaderKeys::values();

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

    protected function createPayload(Request $request, $timestamp, $nonce): string
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
    protected function getSigner(string $type): SignerInterface
    {
        [$brand, $signTypeStr] = array_pad(explode('-', $type, 2), 2, null);

        $brand = strtoupper((string) $brand);
        $signTypeStr = (string) $signTypeStr;
        $configBrand = strtoupper(config('signature.brand'));

        if ($brand === '' || $signTypeStr === '') {
            throw new ValidationException("Invalid auth type format: '{$type}'");
        }

        if ($brand !== $configBrand) {
            throw new ValidationException("Brand mismatch: '{$brand}'");
        }

        if (! $signType = SignType::tryFrom($signTypeStr)) {
            throw new ValidationException("Unsupported sign type: '{$signTypeStr}'");
        }

        return $signType->signer();
    }
}
