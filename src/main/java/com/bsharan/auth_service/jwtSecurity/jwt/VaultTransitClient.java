package com.bsharan.auth_service.jwtSecurity.jwt;

import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.Map;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Component;
import org.springframework.web.client.RestTemplate;

import lombok.RequiredArgsConstructor;

@Component
@RequiredArgsConstructor
public class VaultTransitClient {

    private final RestTemplate restTemplate;

    @Value("${spring.cloud.vault.token}")
    private String vaultToken;

    @Value("${jwt.signing-key-name}")
    private String keyName;

    @Value("${spring.cloud.vault.uri}")
    private String vaultUri;

    public void verify(String unsignedJwt, String signatureBase64) {

        String inputB64 = Base64.getEncoder()
                .encodeToString(unsignedJwt.getBytes(StandardCharsets.UTF_8));

        Map<String, Object> body = Map.of(
                "input", inputB64,
                "signature", "vault:v1:" + signatureBase64
        );

        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_JSON);
        headers.set("X-Vault-Token", vaultToken);

        HttpEntity<Map<String, Object>> request =
                new HttpEntity<>(body, headers);

        ResponseEntity<Map> response =
                restTemplate.postForEntity(
                        vaultUri + "/v1/transit/verify/" + keyName,
                        request,
                        Map.class
                );

        Map<String, Object> data = (Map<String, Object>) response.getBody().get("data");
        if (!(Boolean) data.get("valid")) {
            throw new RuntimeException("Invalid JWT signature");
        }
    }
}
