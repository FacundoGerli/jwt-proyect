package com.jwt.auth.service;

import com.jwt.auth.controller.LoginRequest;
import com.jwt.auth.controller.RegisterRequest;
import com.jwt.auth.controller.TokenResponse;
import com.jwt.auth.model.Token;
import com.jwt.auth.model.TokenType;
import com.jwt.auth.repository.ITokenRepository;
import com.jwt.user.model.Usuario;
import com.jwt.user.repository.IUserRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.List;
import java.util.Optional;

@Service @RequiredArgsConstructor @Slf4j
public class AuthServiceImpl implements IAuthService{

    private final IUserRepository userRepository;
    private final ITokenRepository tokenRepository;
    private final JwtService jwtService;
    private final PasswordEncoder passwordEncoder;
    private final AuthenticationManager authenticationManager;

    @Override
    public TokenResponse register(RegisterRequest request) {
        var user = Usuario.builder()
                .email(request.email())
                .username(request.username())
                .password(passwordEncoder.encode(request.password()))
                .build();
        final var savedUser = userRepository.save(user);
        final String jwt = jwtService.generateToken(savedUser);
        final String refreshToken = jwtService.generateRefreshToken(savedUser);
        saveUserToken(savedUser, jwt);
        log.info("A new user has been created -> {}", savedUser);
        return new TokenResponse(jwt, refreshToken);
    }

    private void saveUserToken(Usuario savedUser, String jwt) {
        var token = Token.builder()
                .token(jwt)
                .user(savedUser)
                .isExpired(false)
                .isRevoked(false)
                .tokenType(TokenType.BEARER)
                .build();
        tokenRepository.save(token);
    }

    @Override
    public TokenResponse login(LoginRequest request) {
        authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(
                        request.email(),
                        request.password()
                )
        );
        var user = userRepository.findByEmail(request.email()).orElseThrow();
        var jwt = jwtService.generateToken(user);
        var refreshToken = jwtService.generateRefreshToken(user);
        revokeAllUserTokens(user);
        saveUserToken(user,jwt);
        return new TokenResponse(jwt,refreshToken);

    }

    private void revokeAllUserTokens(Usuario user) {
        final List<Token> validUserTokens = tokenRepository.findAllValidTokenByUser(user.getId());
        if (!validUserTokens.isEmpty()) {
            for(final Token token : validUserTokens){
                token.setIsRevoked(true);
                token.setIsExpired(true);
            }
            tokenRepository.saveAll(validUserTokens);
        }
    }

    @Override
    public TokenResponse refreshToken(final String authHeader) {
        //verificar primero si el token existe y es valido
        if(authHeader == null || !authHeader.startsWith("Bearer ")){
            throw new IllegalArgumentException("Invalid bearer token");}

        final String refreshToken = authHeader.substring(7);
        final String emailUser = jwtService.extractUsername(refreshToken);

        if (emailUser == null ) {
            throw new IllegalArgumentException("Invalid refresh token");
        }
        final Usuario user = userRepository.findByEmail(emailUser)
                .orElseThrow(() -> new UsernameNotFoundException(emailUser));
        if(!jwtService.isTokenValid(refreshToken,user)){
            throw new IllegalArgumentException("Invalid refresh token");
        }
        final String accessToken = jwtService.generateToken(user);
        revokeAllUserTokens(user);
        saveUserToken(user,accessToken);
        return new TokenResponse(accessToken, refreshToken);
    }
}
