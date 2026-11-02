<?php

return [
    // 应用自己的签名前缀。入站 Authorization 和出站 header 都会带上它，不要包含连字符
    'prefix' => 'your_app',

    // 入站请求有效期，单位秒。时间戳早于或晚于服务器超过这个值会被拒绝，nonce 也按这个时间防重放
    'ttl' => 300,

    // 出站 HTTP 请求超时，单位秒
    'http_timeout' => 60,

    // 跳过有效期检查。只在本地调试时打开
    'skip_ttl_check' => false,

    // 跳过 nonce 重放检查。只在本地调试时打开
    'skip_nonce_check' => false,
];
