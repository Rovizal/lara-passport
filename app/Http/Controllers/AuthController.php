<?php

namespace App\Http\Controllers;

use Illuminate\Http\Request;
use App\Models\ApiLogin;
use Illuminate\Support\Facades\Hash;
// use Carbon\Carbon;

class AuthController extends Controller
{
    protected $expiryAccess;
    protected $expiryRefresh;

    function __construct()
    {
        $this->expiryAccess = now()->addSecond(30);
        $this->expiryRefresh = now()->addMinute(2);
    }

    public function login(Request $request)
    {
        $request->validate([
            'email' => 'required',
            'password' => 'required',
        ]);

        $user = ApiLogin::where('email', $request->email)->first();

        if (!$user || !Hash::check($request->password, $user->password)) {
            return response()->json(['message' => 'Invalid credentials'], 401);
        }

        // Generate JWT access token
        $accessToken = $user->createJwtToken();

        // Generate refresh token
        $refreshToken = bin2hex(random_bytes(40));

        // Simpan token di database
        $user->update([
            'session_id'                => $accessToken,
            'refresh_token'             => $refreshToken,
            'access_token_expiry_time'  => $this->expiryAccess,
            'refresh_token_expiry_time' => $this->expiryRefresh,
        ]);

        // Respons JSON dengan cookie
        return response()->json([
            'access_token'  => $accessToken,
            'expires_at'    => $this->expiryAccess,
        ])->cookie(
            'refresh_token',
            $refreshToken,
            2,
            // 60 * 24 * 7,  // Masa berlaku cookie dalam menit
            '/',
            null,
            app()->environment('production'), // Secure hanya di production
            true,                             // HttpOnly
            false,                            // Raw
            'Strict'                          // SameSite
        );
    }

    public function refreshToken(Request $request)
    {
        // $request->validate([
        //     'refresh_token' => 'required',
        // ]);

        // $refreshToken = $request->cookie('refresh_token');
        // Ambil refresh token dari cookie atau body
        $refreshToken = $request->cookie('refresh_token') ?? $request->input('refresh_token');

        if (!$refreshToken) {
            return response()->json(['message' => 'Refresh token not provided'], 400);
        }

        $user = ApiLogin::where('refresh_token', $refreshToken)
            ->where('refresh_token_expiry_time', '>', now())
            ->first();

        if (!$user) {
            return response()->json(['message' => 'Invalid or expired refresh token'], 401);
        }

        // Generate new access token
        $newAccessToken = $user->createJwtToken();
        $newRefreshToken = bin2hex(random_bytes(40));

        // Update database
        $user->update([
            'session_id'                => $newAccessToken,
            'refresh_token'             => $newRefreshToken,
            'access_token_expiry_time'  => now()->addSeconds(30), // 30 detik lagi
            'refresh_token_expiry_time' => now()->addMinutes(2),  // 2 menit lagi
        ]);

        return response()->json([
            'access_token'  => $newAccessToken,
            'expires_at'    => now()->addSeconds(30),
        ])->cookie(
            'refresh_token',
            $newRefreshToken,
            2, // 2 menit
            '/',
            null,
            app()->environment('production'),
            true, // HttpOnly
            false,
            'Strict'
        );
    }

    public function logout(Request $request)
    {
        // Pastikan user telah diautentikasi
        $user = $request->user;

        if (!$user) {
            return response()->json(['message' => 'User not authenticated'], 401);
        }

        // Hapus token di database
        $user->update([
            'refresh_token'             => null,
            'session_id'                => null,
            'access_token_expiry_time'  => null,
            'refresh_token_expiry_time' => null,
        ]);

        // Hapus cookie refresh_token
        return response()->json(['message' => 'Logged out successfully'])->cookie(
            'refresh_token', // Nama cookie
            '',              // Nilai kosong
            -1,              // Masa berlaku negatif
            '/',             // Path
            null,            // Domain
            app()->environment('production'), // Secure hanya di production
            true,            // HttpOnly
            'Strict'         // SameSite
        );
    }

    public function generatePass()
    {
        $hashedPassword = Hash::make('Abc890123');

        // Cetak hasil
        dd($hashedPassword);
    }
}
