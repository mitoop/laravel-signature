<?php

return [
    'brand' => 'XPAY',
    'max_clock_offset' => 300,
    'http_timeout' => 60,
    'check_clock_offset' => env('SIGNATURE_CHECK_CLOCK_OFFSET', true),
    'check_nonce' => env('SIGNATURE_CHECK_NONCE', true),
];
