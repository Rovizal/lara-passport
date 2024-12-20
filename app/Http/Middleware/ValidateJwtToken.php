<?php

namespace App\Http\Middleware;

use Closure;
use Firebase\JWT\JWT;
use Firebase\JWT\Key;
use App\Models\ApiLogin;

class ValidateJwtToken
{
    public function handle($request, Closure $next)
    {
        $token = $request->bearerToken();

        if (!$token) {
            return response()->json(['message' => 'Unauthorized'], 401);
        }

        try {
            $decoded = JWT::decode($token, new Key(env('JWT_SECRET'), 'HS256'));

            $user = ApiLogin::find($decoded->sub);

            if (!$user || $user->session_id !== $token || $user->access_token_expiry_time < now()) {
                return response()->json(['message' => 'Invalid or expired token'], 401);
            }

            $request->user = $user;
        } catch (\Exception $e) {
            return response()->json(['message' => 'Invalid token', 'error' => $e->getMessage()], 401);
        }

        return $next($request);
    }
}
