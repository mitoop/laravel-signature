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
                return response()->json(['code' => 401, 'message' => 'Invalid signature']);
            }
        } catch (SignatureException $e) {
            return response()->json(['code' => 400, 'message' => $e->getMessage()]);
        } catch (Throwable $e) {
            return response()->json(['code' => 500, 'message' => 'Internal server error']);
        }

        return $next($request);
    }
}
