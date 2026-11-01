# Laravel Signature

用于校验进来的 API 请求，以及给发出去的回调签名。支持 **SHA256-RSA2048**、**SHA256-HMAC** 和 **ED25519**。

入站和出站是两套待签名字符串。入站验的是调用方打过来的请求，出站签的是你发出去的回调。

## 安装

```bash
composer require mitoop/laravel-signature
```

## 配置

```bash
php artisan vendor:publish --tag=config --provider="Mitoop\\LaravelSignature\\ServiceProvider"
```

发布后得到 `config/signature.php`：

```php
return [
    'brand' => 'your_brand',
    'max_clock_offset' => 300,
    'http_timeout' => 60,
    'skip_clock_check' => false,
    'skip_nonce_check' => false,
];
```

`brand` 不要包含连字符。`max_clock_offset` 是入站时间戳允许偏离服务器时间的秒数，过去和未来都算。`http_timeout` 是出站请求的超时时间。两个 `skip_` 只用于本地调试。

## 入站验签

`ValidateSignature` 会检查签名、时钟和 nonce。验签通过之后才会占用 nonce，签名错误不会把这个 nonce 烧掉。

```php
use Mitoop\LaravelSignature\Middlewares\ValidateSignature;

Route::middleware([ValidateSignature::class])->group(function () {
    Route::post('/api/data/cities', [CityController::class, 'index']);
});
```

调用方把凭证放在 `Authorization` 里。`your_brand` 会变成：

```text
YOUR_BRAND-SHA256-RSA2048 mchid="10001",appid="app_001",nonce="abc",timestamp="1710000000",sign="base64 签名"
```

`mchid`、`appid`、`nonce`、`timestamp`、`sign` 都不能空。`nonce` 最长 128 个字符。`timestamp` 是十进制 Unix 秒。

待签名字符串是请求方法、URI、时间戳、随机串和原始 body，每段后面都有换行：

```text
POST
/api/data/cities
1710000000
abc
{"name":"x"}

```

URI 用的是服务器看到的请求 URI，包含查询字符串。

应用资料通过 `ApplicationResolverInterface` 获取。按商户号和应用号返回应用；找不到就返回 `null`。

```php
use Mitoop\LaravelSignature\Validation\ApplicationInterface;
use Mitoop\LaravelSignature\Validation\ApplicationResolverInterface;

class ApplicationResolver implements ApplicationResolverInterface
{
    public function resolve(string $mchId, string $appId): ?ApplicationInterface
    {
        // 返回带有 getAllowedIps()、getSecretKey()、getApplicationId() 的应用
    }
}
```

在 `AppServiceProvider` 里绑定：

```php
$this->app->bind(ApplicationResolverInterface::class, ApplicationResolver::class);
```

验签通过后，可以从上下文取出这个应用：

```php
app(\Mitoop\LaravelSignature\Validation\Context::class)->get('application');
```

HTTP 状态保持 200。签名不对时正文是 `{"code":401,"message":"Invalid signature"}`。参数、时钟、IP 或重放问题的 `code` 是 `400`，`message` 是具体原因。

## 出站回调

`Client` 用来给回调签名并发送。默认算法是 `SHA256-RSA2048`。

```php
use Mitoop\LaravelSignature\Http\Client;
use Mitoop\LaravelSignature\Signer\SignType;

$response = app(Client::class)
    ->useSigner(SignType::SHA256_HMAC)
    ->post('https://outer-service.com/api/notify', [
        'order_id' => '123456',
        'status' => 'success',
    ], 'platform-private-key');
```

待签名字符串是时间戳、随机串和 JSON 原文，每段后面都有换行。签名覆盖的就是发出去的那份 body。

品牌 `your_brand` 会生成这些头：

```text
Your_brand-Nonce
Your_brand-Signature
Your_brand-Signature-Type: YOUR_BRAND-SHA256-RSA2048
Your_brand-Timestamp
```

对方的 HTTP 状态是 2xx，并且响应正文正好是 `success` 时，`$response->ok()` 为真。

## 参考

- [微信支付 API v3](https://wechatpay-api.gitbook.io/wechatpay-api-v3)
- [支付宝开放平台 v3](https://opendocs.alipay.com/open-v3/054kaq)
