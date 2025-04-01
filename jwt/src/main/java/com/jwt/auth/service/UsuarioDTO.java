package com.jwt.auth.service;

import lombok.Builder;

@Builder
public record UsuarioDTO(
        String username,
        String email,
        String token
) {
}