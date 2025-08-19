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

        $localTimestamp = time();

        if (! config('signature.skip_clock_check')
            && abs($localTimestamp - $timestamp) > config('signature.max_clock_offset')) {
            throw new ValidationException(sprintf(
                '时间偏差过大，当前时间为：%s，提供的时间为：%s，允许的最大偏差为：%d 秒。',
                $localTimestamp,
                $timestamp,
                config('signature.max_clock_offset')
            ));
        }

        $application = $this->getApplication($mchId, $appId);

        $allowedIps = $application->getAllowedIps();

        if ($allowedIps && ! in_array($request->ip(), $allowedIps, true)) {
            throw new ValidationException('IP 地址不在白名单中');
        }

        if (! config('signature.skip_nonce_check')
            &&
            ! Cache::add(sprintf('mitoop_signature:%s:%s', $application->getApplicationId(), $nonce), 1, config('signature.max_clock_offset'))) {
            throw new ValidationException('请勿重复发送相同请求');
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
            throw new ValidationException('Authorization 不能为空');
        }

        $parts = explode(' ', $authorization, 2);

        if (count($parts) !== 2) {
            throw new ValidationException('签名格式不正确');
        }

        $data = ['type' => $parts[0]];
        $items = explode(',', $parts[1]);

        $requiredKeys = RequestHeaderKeys::values();
        foreach ($items as $item) {
            $parts = explode('=', $item, 2);

            if (count($parts) !== 2) {
                throw new ValidationException('签名格式不正确');
            }

            [$key, $value] = array_map('trim', $parts);

            if (in_array($key, $requiredKeys, true)) {
                $value = trim($value, '"');
                if (empty($value)) {
                    throw new ValidationException(sprintf('%s 值不能为空', $key));
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
                throw new ValidationException(sprintf('缺少 %s', $key));
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
            throw new RuntimeException('未绑定应用解析器');
        }

        $application = app(ApplicationResolverInterface::class)->resolve($mchId, $appId);

        if (! $application) {
            throw new ValidationException(sprintf('商户ID %s 或应用ID %s 错误', $mchId, $appId));
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
            throw new ValidationException("认证类型格式错误: '{$type}'");
        }

        if ($brand !== $configBrand) {
            throw new ValidationException("品牌不匹配: '{$brand}'");
        }

        if (! $signType = SignType::tryFrom($signTypeStr)) {
            throw new ValidationException("不支持的签名类型: '{$signTypeStr}'");
        }

        return $signType->signer();
    }
}
