package com.emailsender.service;

public record UsuarioDTO(
        String username,
        String email,
        String token
) {
}
