<?php

namespace Mitoop\LaravelSignature\Middlewares;

use Closure;
use Illuminate\Http\Request;
use Mitoop\LaravelSignature\Exceptions\SignatureException;
use Mitoop\LaravelSignature\Validation\Validator;
use Throwable;

class ValidateSignature
{
    public function handle(Request $request, Closure $next)
    {
        try {
            if (! app(Validator::class)->pass($request)) {
                return response()->json([
                    'code' => 102,
                    'message' => '签名错误',
                ]);
            }
        } catch (SignatureException $e) {
            return response()->json([
                'code' => 101,
                'message' => $e->getMessage(),
            ]);
        } catch (Throwable $e) {
            return response()->json([
                'code' => 500,
                'message' => '系统内部错误',
            ]);
        }

        return $next($request);
    }
}
