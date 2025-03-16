package com.jwt.auth.service;

import com.jwt.auth.controller.LoginRequest;
import com.jwt.auth.controller.RegisterRequest;
import com.jwt.auth.controller.TokenResponse;

public interface IAuthService {
    TokenResponse login(LoginRequest request);
    TokenResponse register(RegisterRequest request);
    TokenResponse refreshToken(String auth);
}
