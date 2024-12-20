<?php

namespace App\Models;

use Illuminate\Foundation\Auth\User as Authenticatable;
use Laravel\Passport\HasApiTokens;
use Firebase\JWT\JWT;

class ApiLogin extends Authenticatable
{
    use HasApiTokens;

    protected $table = 'api_login'; // Tabel kustom
    protected $primaryKey = 'id';

    public $timestamps = false;

    protected $fillable = [
        'email',
        'login_id',
        'password',
        'session_id',
        'refresh_token',
        'access_token_expiry_time',
        'refresh_token_expiry_time',
    ];

    protected $hidden = [
        'password',
        'refresh_token',
        'email_sosmed',
        'session_id',
        'access_token_expiry_time',
        'refresh_token_expiry_time'
    ];

    // Metode untuk membuat JWT
    public function createJwtToken()
    {
        $payload = [
            'iss' => env('APP_URL'), // Issuer
            'sub' => $this->id, // ID pengguna
            'sess_id' => $this->login_id, // Login ID pengguna
            'iat' => time(), // Waktu token dibuat
            'exp' => time() + 3600, // Kadaluwarsa token (1 jam)
        ];

        return JWT::encode($payload, env('JWT_SECRET'), 'HS256');
    }
}
