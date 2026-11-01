<?php

return [
    // 签名品牌。入站 Authorization 和出站 header 都会带上它，不要包含连字符
    'brand' => 'your_brand',

    // 允许的时钟偏差，单位秒。入站时间戳早于或晚于服务器超过这个值会被拒绝
    'max_clock_offset' => 300,

    // 出站 HTTP 请求超时，单位秒
    'http_timeout' => 60,

    // 跳过时钟检查。只在本地调试时打开
    'skip_clock_check' => false,

    // 跳过 nonce 重放检查。只在本地调试时打开
    'skip_nonce_check' => false,
];
