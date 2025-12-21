package com.bsharan.auth_service.jwtSecurity.jwt;

import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.List;
import java.util.Map;
import java.util.UUID;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.stereotype.Component;

@Component
public class JwtClaimsParser {

    private final ObjectMapper mapper = new ObjectMapper();

    public JwtClaims parse(String jwt) throws Exception {

        String[] parts = jwt.split("\\.");
        if (parts.length != 3) {
            throw new IllegalArgumentException("Invalid JWT");
        }

        String payloadJson =
                new String(
                        Base64.getUrlDecoder().decode(parts[1]),
                        StandardCharsets.UTF_8
                );

        Map<String, Object> claims =
                mapper.readValue(payloadJson, Map.class);

        UUID userId = UUID.fromString((String) claims.get("sub"));
        String email = (String) claims.get("email");
        List<String> roles = (List<String>) claims.get("roles");

        return new JwtClaims(userId, email, roles);
    }
}
