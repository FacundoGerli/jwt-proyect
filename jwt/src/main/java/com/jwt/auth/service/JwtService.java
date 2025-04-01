package com.jwt.auth.service;

import com.jwt.user.model.Usuario;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import javax.crypto.SecretKey;
import java.util.Date;
import java.util.Map;
import java.util.Optional;

@Service
public class JwtService {
    @Value("${spring.security.jwt.secret-key}")
    private String secretKey;
    @Value("${spring.security.jwt.expiration}")
    private long expiration;
    @Value("${spring.security.jwt.expiration.refresh-token}")
    private long expirationRefreshToken;
    @Value("${spring.security.jwt.verifyExpiration}")
    private long expirationVerificationToken;

    public String generateToken(final Usuario user){
        return buildToken(user,expiration);
    }

    public String generateRefreshToken(Usuario user) {
        return buildToken(user,expirationRefreshToken);
    }
    public String generateVerifyToken(Usuario user){
        return buildToken(user, expirationVerificationToken);
    }

    private String buildToken(final Usuario user, final long expiration) {
        return Jwts.builder()
                .id(user.getId().toString())
                .claims(Map.of("name", user.getUsername()))
                .subject(user.getEmail())
                .issuedAt(new Date(System.currentTimeMillis()))
                .expiration(new Date(System.currentTimeMillis() + expiration))
                .signWith(getSignKey())
                .compact();
    }
    private SecretKey getSignKey(){
        byte[] keyBytes = Decoders.BASE64.decode(secretKey);
        return Keys.hmacShaKeyFor(keyBytes);
    }
    public String extractUsername(final String token){
        final Claims jwt = getPayload(token);
        return jwt.getSubject();
    }

    private Claims getPayload(String token) {
        final Claims jwt = Jwts.parser()
                .verifyWith(getSignKey())
                .build()
                .parseSignedClaims(token)
                .getPayload();
        return jwt;
    }

    public boolean isTokenValid(final String refreshToken, final Usuario user) {
        final String username = extractUsername(refreshToken);
        return (user.getEmail().equals(username) && !isTokenExpired(refreshToken));
    }

    private boolean isTokenExpired(String token) {
        return extractExpiration(token).before(new Date());
    }

    private Date extractExpiration(final String token) {
        return getPayload(token).getExpiration();
    }
}
