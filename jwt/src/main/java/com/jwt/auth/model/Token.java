package com.jwt.auth.model;


import com.jwt.user.model.Usuario;
import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Entity @Builder @Data @AllArgsConstructor @NoArgsConstructor
public class Token {
    @Id
    @GeneratedValue(strategy = GenerationType.AUTO)
    private Long id;
    private String token;
    @Builder.Default
    private TokenType tokenType = TokenType.BEARER;
    private Boolean isRevoked;
    private Boolean isExpired;
    @ManyToOne(fetch= FetchType.LAZY)
    @JoinColumn(name = "user_id")
    private Usuario user;

}
