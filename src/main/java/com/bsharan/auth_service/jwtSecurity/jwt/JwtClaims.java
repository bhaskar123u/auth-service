package com.bsharan.auth_service.jwtSecurity.jwt;

import java.util.List;
import java.util.UUID;

public class JwtClaims {

    private final UUID userId;
    private final String email;
    private final List<String> roles;

    public JwtClaims(UUID userId, String email, List<String> roles) {
        this.userId = userId;
        this.email = email;
        this.roles = roles;
    }

    public UUID getUserId() {
        return userId;
    }

    public String getEmail() {
        return email;
    }

    public List<String> getRoles() {
        return roles;
    }
}
