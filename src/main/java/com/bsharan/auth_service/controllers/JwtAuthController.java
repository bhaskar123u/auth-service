package com.bsharan.auth_service.controllers;

import com.bsharan.auth_service.dtos.JwtLoginRequest;
import com.bsharan.auth_service.dtos.JwtLoginResponse;
import com.bsharan.auth_service.jwtSecurity.jwt.JwtTokenService;
import com.bsharan.auth_service.jwtSecurity.jwt.TokenBlacklist;
import com.bsharan.auth_service.jwtSecurity.userdetails.JwtUserDetails;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/v1/auth/jwt")
@RequiredArgsConstructor
public class JwtAuthController {

    private final AuthenticationManager authenticationManager;
    private final JwtTokenService jwtTokenService;
    private final TokenBlacklist tokenBlacklist;

    @PostMapping("/login")
    public ResponseEntity<JwtLoginResponse> login(
            @RequestBody JwtLoginRequest request
    ) throws Exception {

        Authentication authentication =
                authenticationManager.authenticate(
                        new UsernamePasswordAuthenticationToken(
                                request.getEmail(),
                                request.getPassword()
                        )
                );

        JwtUserDetails principal =
                (JwtUserDetails) authentication.getPrincipal();

        String token = jwtTokenService.generateToken(
                principal.getUserId(),
                principal.getEmail(),
                principal.getAuthorities()
                        .stream()
                        .map(a -> a.getAuthority())
                        .toList()
        );

        return ResponseEntity.ok(
                new JwtLoginResponse(
                        token,
                        "Bearer",
                        jwtTokenService.getExpiryEpochSeconds()
                )
        );
    }

    @PostMapping("/logout")
    public ResponseEntity<Void> logout(
            @RequestHeader("Authorization") String auth
    ) {
        if (auth != null && auth.startsWith("Bearer ")) {
            tokenBlacklist.blacklist(auth.substring(7));
        }
        return ResponseEntity.ok().build();
    }
}
