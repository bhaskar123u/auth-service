package com.bsharan.auth_service.jwtSecurity.jwt;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.stereotype.Service;

import java.util.Base64;
import java.util.Map;

@Service
public class VaultTransitJwtService {

    private final ObjectMapper objectMapper = new ObjectMapper();

    public Map<String, Object> verifyAndExtractClaims(String jwt) throws Exception {

        String[] parts = jwt.split("\\.");
        if (parts.length != 3) {
            throw new RuntimeException("Invalid JWT format");
        }

        byte[] payloadBytes = Base64.getUrlDecoder().decode(parts[1]);
        String payloadJson = new String(payloadBytes);

        return objectMapper.readValue(payloadJson, Map.class);
    }
}
