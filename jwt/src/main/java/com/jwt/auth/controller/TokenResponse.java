package com.jwt.auth.controller;

public record TokenResponse(
        String jwtToken,
        String refreshToken) {
}
