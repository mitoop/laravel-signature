# Laravel Signature

Laravel Signature 为 API 提供入站验签和出站回调签名。支持 **SHA256-RSA2048**、**SHA256-HMAC** 和 **ED25519**。`ED25519` 的认证方案名就是 `ED25519`，内部使用 SHA-512。同一服务可接入多个商户，每个商户可有多个应用。

入站和出站各有一条待签名字符串。入站覆盖调用方的原始请求，出站覆盖本次发出的回调正文。接收方按对应格式验签。

## 环境要求

* PHP ^8.2
* Laravel ^11.0 | ^12.0 | ^13.0

## 安装

通过 Composer 安装：

```shell
composer require mitoop/laravel-signature
```

## 配置

发布配置文件：

```shell
php artisan vendor:publish --tag=config --provider="Mitoop\\LaravelSignature\\ServiceProvider"
```

`config/signature.php` 的默认值如下：

| 配置 | 默认值 | 说明 |
| --- | --- | --- |
| `prefix` | `your_app` | 应用的签名前缀。入站写进认证方案名，出站写进回调头 |
| `ttl` | `300` | 入站请求有效期，单位秒。nonce 按同一时长防重放 |
| `http_timeout` | `60` | 出站 HTTP 请求超时，单位秒 |
| `skip_ttl_check` | `false` | 跳过有效期检查。仅用于本地调试 |
| `skip_nonce_check` | `false` | 跳过 nonce 重放检查。仅用于本地调试 |

`prefix` 不能包含连字符。认证方案名以第一个 `-` 分隔前缀和算法，比较时忽略大小写。生产环境保持两个 `skip_` 为 `false`。

## 入站验签

`ValidateSignature` 是一份参考实现。

```php
use Mitoop\LaravelSignature\Middlewares\ValidateSignature;

Route::middleware([ValidateSignature::class])->group(function () {
    Route::post('/api/payments', [PaymentController::class, 'store']);
});
```

校验按以下顺序进行：

1. 解析 `Authorization`。
2. 匹配 `prefix` 和签名算法。
3. 按商户号、应用号解析应用。
4. 检查来源 IP。应用未配置白名单时跳过。
5. 验签。失败则拒绝。
6. 检查请求有效期。时间戳早于或晚于服务器超过 `ttl` 秒则拒绝。
7. 占用 nonce。同一应用在 `ttl` 秒内重复提交同一 nonce 则拒绝。
8. 将应用写入上下文。

### 认证头

调用方将凭证放在 `Authorization` 中。`prefix` 为 `your_app`、算法为 `SHA256-RSA2048` 时：

```text
YOUR_APP-SHA256-RSA2048 mchid="10001",appid="app_001",nonce="abc",timestamp="1710000000",sign="base64 签名"
```

`mchid`、`appid`、`nonce`、`timestamp` 和 `sign` 均不能为空。`mchid` 是商户号，`appid` 是该商户下的应用号。`nonce` 最长 128 个字符。`timestamp` 为十进制 Unix 秒。

商户为每个应用生成一对公私钥，私钥自己保存，公钥放到平台。请求由商户私钥签名，平台用该应用的公钥验签。`SHA256-HMAC` 没有公私钥，商户和平台共用同一把密钥。

### 待签名字符串

待签名字符串由请求方法、URI、时间戳、nonce 和原始 body 组成。每段以 `\n` 结束，包括最后一段：

```text
POST\n
/api/payments\n
1710000000\n
abc\n
{"order_id":"123456","amount":100}\n
```

请求方法使用大写。URI 为服务端收到的请求 URI，包含查询字符串。body 使用原始报文，不重新编码。

### 应用解析

实现 `ApplicationResolverInterface`，按商户号和应用号返回应用。同一商户下的不同应用各自拥有密钥、来源 IP 白名单和应用标识。找不到时返回 `null`。

```php
use Mitoop\LaravelSignature\Validation\ApplicationInterface;
use Mitoop\LaravelSignature\Validation\ApplicationResolverInterface;

class ApplicationResolver implements ApplicationResolverInterface
{
    public function resolve(string $mchId, string $appId): ?ApplicationInterface
    {
        // 返回实现了 getAllowedIps()、getKey()、getApplicationId() 的应用
    }
}
```

在 `AppServiceProvider` 中绑定：

```php
$this->app->bind(ApplicationResolverInterface::class, ApplicationResolver::class);
```

验签通过后，从上下文读取该应用：

```php
app(\Mitoop\LaravelSignature\Validation\Context::class)->get('application');
```

### 响应

下面是 `ValidateSignature` 拒绝请求时的返回示例，HTTP 状态为 `200`。

| 场景 | 正文 |
| --- | --- |
| 签名不匹配 | `{"code":401,"message":"Invalid signature"}` |
| 认证头、有效期、来源 IP 或重放 | `{"code":400,"message":"具体原因"}` |
| 未预期的错误 | `{"code":500,"message":"Internal server error"}` |

未预期的错误会先写入应用日志。

## 出站回调

`Client` 对回调签名并发送。默认算法为 `SHA256-RSA2048`。每次调用单独指定算法，该选择只作用于这一次请求。

```php
use Mitoop\LaravelSignature\Http\Client;
use Mitoop\LaravelSignature\Signer\SignType;

$response = app(Client::class)
    ->useSigner(SignType::SHA256_RSA2048)
    ->post('https://outer-service.com/api/notify', [
        'order_id' => '123456',
        'status' => 'success',
    ], 'platform-private-key');
```

平台为每个商户的每个应用生成一对公私钥，或一把密钥。第三个参数是平台保存的私钥或密钥。使用公私钥时，平台把对应的公钥交给该应用，商户用这把公钥验证回调。`SHA256-HMAC` 没有公私钥，双方使用同一把密钥。

待签名字符串由时间戳、nonce 和 JSON 正文组成。每段以 `\n` 结束，包括最后一段。签名覆盖的是实际发出的那份正文：

```text
1710000000\n
abc\n
{"order_id":"123456","status":"success"}\n
```

`prefix` 为 `your_app` 时，回调携带以下请求头：

```text
Your_app-Nonce
Your_app-Signature
Your_app-Signature-Type: YOUR_APP-SHA256-RSA2048
Your_app-Timestamp
```

头名称中的前缀为小写后的首字母大写。`Signature-Type` 的值为前缀和算法，整体大写。

接收方返回 HTTP `2xx`，且响应正文恰好为 `success` 时，`$response->ok()` 为 `true`。

## 参考

- [微信支付 API v3](https://wechatpay-api.gitbook.io/wechatpay-api-v3)
- [支付宝开放平台 v3](https://opendocs.alipay.com/open-v3/054kaq)
