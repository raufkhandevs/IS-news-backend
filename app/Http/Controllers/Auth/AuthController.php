<?php

namespace App\Http\Controllers\Auth;

use App\Http\Controllers\Controller;
use Illuminate\Http\Request;
use App\Http\Requests\Auth\RegisterRequest;
use App\Http\Requests\Auth\LoginRequest;
use App\Models\User;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Hash;
use Illuminate\Validation\ValidationException;
use App\Http\Resources\Auth\UserResource;

class AuthController extends Controller
{
    /**
     * register a new user
     *
     * @param Request $request
     * @return void
     */
    public function register(RegisterRequest $request)
    {
        $user = User::create([
            'name' => $request->name,
            'email' => $request->email,
            'password' => Hash::make($request->password),
        ]);

        // Issue token
        $token = $user->createToken('auth_token')->plainTextToken;

        return response()->json([
            'user'         => new UserResource($user),
            'access_token' => $token,
            'token_type'   => 'Bearer',
        ]);
    }

    /**
     * login a user
     *
     * @param Request $request
     * @return void
     */
    public function login(LoginRequest $request)
    {
        $credentials = $request->only('email', 'password');

        if (!Auth::attempt($credentials)) {
            throw ValidationException::withMessages([
                'email' => ['The provided credentials are incorrect.'],
            ]);
        }

        $user = Auth::user();
        $token = $user->createToken('auth_token')->plainTextToken;

        return response()->json([
            'user'         => new UserResource($user),
            'access_token' => $token,
            'token_type'   => 'Bearer',
        ]);
    }

    /**
     * show authenticated user
     *
     * @param Request $request
     * @return void
     */
    public function user(Request $request)
    {
        return new UserResource($request->user());
    }

    /**
     * logout a user
     *
     * @param Request $request
     * @return void
     */
    public function logout(Request $request)
    {
        $request->user()->tokens()->delete();

        return response()->json([
            'message' => 'Successfully logged out'
        ]);
    }
}
