package com.jwt.auth.controller;

import com.jwt.auth.service.IAuthService;
import lombok.RequiredArgsConstructor;
import org.springframework.boot.actuate.autoconfigure.observation.ObservationProperties;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.*;

@RestController @RequiredArgsConstructor
@RequestMapping("/auth")
public class AuthController {
    private final IAuthService authService;

    @ResponseStatus(HttpStatus.OK)
    @PostMapping("/register")
    public TokenResponse register(@RequestBody RegisterRequest request){
        return authService.register(request);
    }
    @ResponseStatus(HttpStatus.OK)
    @PostMapping("/login")
    public TokenResponse login(@RequestBody LoginRequest request){
        return authService.login(request);
    }
    @ResponseStatus(HttpStatus.OK)
    @PostMapping("/refresh")
    public TokenResponse refreshToken(
            @RequestHeader(HttpHeaders.AUTHORIZATION) final String auth){
        return authService.refreshToken(auth);
    }
    @GetMapping("/verify/{token}")
    public String verifyUser(@PathVariable String token){
        return authService.verifyUser(token);
    }
}
