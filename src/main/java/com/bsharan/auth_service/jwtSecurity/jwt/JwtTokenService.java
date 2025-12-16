package com.bsharan.auth_service.jwtSecurity.jwt;

import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.Base64;
import java.util.List;
import java.util.Map;
import java.util.UUID;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.stereotype.Service;
import org.springframework.vault.core.VaultTemplate;
import org.springframework.vault.support.VaultResponse;

import com.bsharan.auth_service.dtos.JwtLoginResponse;
import com.bsharan.auth_service.jwtSecurity.userdetails.JwtUserDetails;
import com.fasterxml.jackson.databind.ObjectMapper;

import lombok.RequiredArgsConstructor;

@Service
@RequiredArgsConstructor
public class JwtTokenService {

    private final VaultTemplate vaultTemplate;
    private final ObjectMapper objectMapper;

    @Value("${jwt.access-token-ttl}")
    private long accessTokenTtlSeconds;

    @Value("${jwt.signing-key-name}")
    private String jwtSigningKeyName;

    @Value("${jwt.issuer}")
    private String jwtIssuer;

    public JwtLoginResponse createJwtToken(Authentication authentication) {
        try {
            // 1. Extract authenticated principal
            /* org.springframework.security.core.userdetails.User principal =
                            (org.springframework.security.core.userdetails.User) authentication.getPrincipal(); */
            JwtUserDetails principal = (JwtUserDetails) authentication.getPrincipal();
            String email = principal.getUsername();
            UUID userId = principal.getUserId();
            List<String> roles = authentication.getAuthorities().stream()
                    .map(GrantedAuthority::getAuthority)
                    .toList();

            long now = Instant.now().getEpochSecond();
            long expiry = now + accessTokenTtlSeconds;

            // 2. JWT Header
            Map<String, Object> header = Map.of(
                    "alg", "RS256",
                    "typ", "JWT"
            );

            // 3. JWT Payload
            Map<String, Object> payload = Map.of(
                    "sub", userId,
                    "email", email,
                    "roles", roles,
                    "iat", now,
                    "exp", expiry,
                    "iss", jwtIssuer
            );

            // 4. Base64URL encode header & payload
            String encodedHeader = base64UrlEncode(objectMapper.writeValueAsBytes(header));
            String encodedPayload = base64UrlEncode(objectMapper.writeValueAsBytes(payload));

            String signingInput = encodedHeader + "." + encodedPayload;

            // 5. Vault expects Base64 (NOT Base64URL)
            String signingInputBase64 =
                    Base64.getEncoder().encodeToString(signingInput.getBytes(StandardCharsets.UTF_8));

            Map<String, Object> signRequest = Map.of(
                    "input", signingInputBase64
            );

            VaultResponse response = vaultTemplate.write(
                    "transit/sign/" + jwtSigningKeyName,
                    signRequest
            );

            String vaultSignature = (String) response.getData().get("signature");

            // response from vault -> vault:v1:<base64-signature>
            String base64Signature = vaultSignature.substring("vault:v1:".length());

            // Convert to Base64URL (JWT requirement)
            String jwtSignature = base64UrlEncode(
                    Base64.getDecoder().decode(base64Signature)
            );

            // 6. Final JWT
            String jwt = encodedHeader + "." + encodedPayload + "." + jwtSignature;
            return new JwtLoginResponse(jwt, "Bearer", expiry);
        } catch (Exception e) {
            throw new IllegalStateException("Failed to create JWT", e);
        }
    }

    private String base64UrlEncode(byte[] data) {
        return Base64.getUrlEncoder()
                .withoutPadding()
                .encodeToString(data);
    }
}

