package com.bsharan.auth_service.jwtSecurity.jwt;

import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.*;
import org.springframework.security.authentication.InsufficientAuthenticationException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;
import org.springframework.web.client.RestTemplate;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.*;

@Component
@RequiredArgsConstructor
public class JwtAuthenticationFilter extends OncePerRequestFilter {

    private final RestTemplate restTemplate;
    private final TokenBlacklist tokenBlacklist;

    private final ObjectMapper objectMapper = new ObjectMapper();

    @Value("${spring.cloud.vault.uri}")
    private String vaultUri;

    @Value("${spring.cloud.vault.token}")
    private String vaultToken;

    @Value("${jwt.signing-key-name}")
    private String keyName;

    @Override
    protected void doFilterInternal(
            HttpServletRequest request,
            HttpServletResponse response,
            FilterChain filterChain
    ) throws ServletException, IOException {

        String authHeader = request.getHeader("Authorization");

        if (authHeader == null || !authHeader.startsWith("Bearer ")) {
            throw new org.springframework.security.authentication.AuthenticationCredentialsNotFoundException(
            "JWT token is missing");
        }

        String jwt = authHeader.substring(7);

        if (tokenBlacklist.isBlacklisted(jwt)) {
            throw new InsufficientAuthenticationException("Token is revoked");
        }

        String[] parts = jwt.split("\\.");
        if (parts.length != 3) {
            throw new InsufficientAuthenticationException("Malformed JWT");
        }

        String signingInput = parts[0] + "." + parts[1];
        String signature = parts[2];

        if (!verifyWithVault(signingInput, signature)) {
            throw new InsufficientAuthenticationException("Invalid JWT signature");
        }

        byte[] payloadBytes;
        try {
            payloadBytes = Base64.getUrlDecoder().decode(parts[1]);
        } catch (IllegalArgumentException ex) {
            response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
            return;
        }

        Map<String, Object> claims =
                objectMapper.readValue(payloadBytes, Map.class);

        String email = (String) claims.get("email");
        String subject = (String) claims.get("sub");
        List<String> roles = (List<String>) claims.get("roles");

        if (email == null || roles == null) {
            response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
            return;
        }

        List<SimpleGrantedAuthority> authorities =
        roles.stream()
                .map(role -> role.startsWith("ROLE_")
                        ? role
                        : "ROLE_" + role)
                .map(SimpleGrantedAuthority::new)
                .toList();

        UsernamePasswordAuthenticationToken authentication =
                new UsernamePasswordAuthenticationToken(
                        email,   // principal = email (important for @PreAuthorize)
                        null,
                        authorities
                );

        SecurityContextHolder.getContext().setAuthentication(authentication);
        filterChain.doFilter(request, response);
    }


    private boolean verifyWithVault(String input, String signature) {

            String inputB64 = Base64.getEncoder()
                            .encodeToString(input.getBytes(StandardCharsets.UTF_8));

            HttpHeaders headers = new HttpHeaders();
            headers.setContentType(MediaType.APPLICATION_JSON);
            headers.set("X-Vault-Token", vaultToken);

            Map<String, Object> body = new HashMap<>();
            body.put("input", inputB64);
            body.put("signature", "vault:v1:" + signature);

            HttpEntity<Map<String, Object>> request = new HttpEntity<>(body, headers);

            ResponseEntity<Map> response = restTemplate.postForEntity(
                            vaultUri + "/v1/transit/verify/" + keyName,
                            request,
                            Map.class);

            Map<String, Object> data = (Map<String, Object>) response.getBody().get("data");

            return Boolean.TRUE.equals(data.get("valid"));
    }
    
    @Override
    protected boolean shouldNotFilter(HttpServletRequest request) {
        String path = request.getRequestURI();

        return path.equals("/api/v1/auth/register")
                || path.equals("/api/v1/auth/jwt/login");
    }
}
