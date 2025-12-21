package com.bsharan.auth_service.jwtSecurity.jwt;

import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.*;
import org.springframework.stereotype.Service;
import org.springframework.web.client.RestTemplate;

import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.*;

@Service
@RequiredArgsConstructor
public class JwtTokenService {

    private final RestTemplate restTemplate;
    private final ObjectMapper objectMapper = new ObjectMapper();

    @Value("${spring.cloud.vault.uri}")
    private String vaultUri;

    @Value("${spring.cloud.vault.token}")
    private String vaultToken;

    @Value("${jwt.signing-key-name}")
    private String keyName;

    @Value("${jwt.access-token-ttl}")
    private long ttlSeconds;

    public String generateToken(
            UUID userId,
            String email,
            List<String> roles
    ) throws Exception {

        Map<String, Object> header = Map.of(
                "alg", "RS256",
                "typ", "JWT"
        );

        Map<String, Object> payload = new HashMap<>();
        payload.put("sub", userId.toString());
        payload.put("email", email);
        payload.put("roles", roles);
        payload.put("iat", Instant.now().getEpochSecond());
        payload.put("exp", Instant.now().getEpochSecond() + ttlSeconds);

        String headerB64 = base64Url(objectMapper.writeValueAsBytes(header));
        String payloadB64 = base64Url(objectMapper.writeValueAsBytes(payload));

        String signingInput = headerB64 + "." + payloadB64;

        String signature = signWithVault(signingInput);

        return signingInput + "." + signature;
    }

    public long getExpiryEpochSeconds() {
        return Instant.now().getEpochSecond() + ttlSeconds;
    }

    private String signWithVault(String input) {

        String inputB64 = Base64.getEncoder()
                .encodeToString(input.getBytes(StandardCharsets.UTF_8));

        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_JSON);
        headers.set("X-Vault-Token", vaultToken);

        Map<String, Object> body = Map.of("input", inputB64);

        HttpEntity<Map<String, Object>> request =
                new HttpEntity<>(body, headers);

        ResponseEntity<Map> response =
                restTemplate.postForEntity(
                        vaultUri + "/v1/transit/sign/" + keyName,
                        request,
                        Map.class
                );

        Map<String, Object> data =
                (Map<String, Object>) response.getBody().get("data");

        String sig = (String) data.get("signature");
        return sig.replace("vault:v1:", "");
    }

    private String base64Url(byte[] bytes) {
        return Base64.getUrlEncoder()
                .withoutPadding()
                .encodeToString(bytes);
    }
}
