<?php

namespace App\Http\Middleware;

use Closure;
use Firebase\JWT\JWT;
use Firebase\JWT\Key;
use App\Models\ApiLogin;

class ApiTokenMiddleware
{
    public function handle($request, Closure $next)
    {
        $token = $request->bearerToken();

        if (!$token) {
            return response()->json(['message' => 'Unauthorized'], 401);
        }

        try {
            // Decode JWT
            $decoded = JWT::decode($token, new Key(env('JWT_SECRET'), 'HS256'));

            // Ambil user dari database
            $user = ApiLogin::find($decoded->sub);

            if (!$user) {
                return response()->json(['message' => 'User not found'], 404);
            }

            // Set user ke request
            $request->user = $user;
        } catch (\Exception $e) {
            return response()->json(['message' => 'Invalid or expired token', 'error' => $e->getMessage()], 401);
        }

        return $next($request);
    }
}
