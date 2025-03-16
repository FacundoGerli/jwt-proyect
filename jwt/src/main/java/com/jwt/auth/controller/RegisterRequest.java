package com.jwt.auth.controller;

public record RegisterRequest(
        String email,
        String username,
        String password
) {
}
