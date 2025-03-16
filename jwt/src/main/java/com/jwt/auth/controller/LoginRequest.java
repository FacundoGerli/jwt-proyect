package com.jwt.auth.controller;

public record LoginRequest(
        String email,
        String password
) {
}
