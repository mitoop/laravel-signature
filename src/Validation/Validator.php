<?php

namespace Mitoop\LaravelSignature\Validation;

use Illuminate\Http\Request;
use Illuminate\Support\Facades\Cache;
use Mitoop\LaravelSignature\Exceptions\UnboundException;
use Mitoop\LaravelSignature\Exceptions\ValidationException;
use Mitoop\LaravelSignature\Signer\SignerInterface;

class Validator
{
    public function __construct(protected array $signers) {}

    /**
     * @throws ValidationException
     * @throws UnboundException
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

        if (abs($localTimestamp - $timestamp) > config('signature.max_clock_offset')) {
            throw new ValidationException(sprintf(
                '时间偏差过大，当前时间为：%s，提供的时间为：%s，允许的最大偏差为：%d 秒。',
                $localTimestamp,
                $timestamp,
                config('signature.max_clock_offset')
            ));
        }

        $application = $this->getApplication($mchId, $appId);

        if (in_array($request->ip, $application->getAllowedIps(), true)) {
            throw new ValidationException('IP 地址不在白名单中');
        }

        if (! Cache::add($application->getApplicationId().':'.$nonce, 1, config('signature.max_clock_offset'))) {
            throw new ValidationException('请勿重复发送相同请求');
        }

        $signer = $this->getSigner($type);

        return tap($signer->verify(
            $this->createPayload($request, $timestamp, $nonce),
            $application->getSecretKey(),
            $sign,
        ), fn () => app(Context::class)->set('application', $application));
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
     * @throws UnboundException
     * @throws ValidationException
     */
    protected function getApplication(string $mchId, string $appId): ApplicationInterface
    {
        if (! app()->bound(ApplicationResolverInterface::class)) {
            throw new UnboundException('未绑定应用解析器');
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
        if (isset($this->signers[$type])) {
            return new $this->signers[$type];
        }

        throw new ValidationException(sprintf('认证类型 %s 错误', $type));
    }
}
