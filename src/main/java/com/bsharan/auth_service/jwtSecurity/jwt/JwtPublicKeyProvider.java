package com.bsharan.auth_service.jwtSecurity.jwt;

import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.Map;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;
import org.springframework.vault.core.VaultTemplate;
import org.springframework.vault.support.VaultResponse;

import lombok.RequiredArgsConstructor;

@Component
@RequiredArgsConstructor
public class JwtPublicKeyProvider {

    private final VaultTemplate vaultTemplate;

    @Value("${jwt.signing-key-name}")
    private String signingKeyName;

    private volatile PublicKey cachedKey;

    public PublicKey getPublicKey() {
        if (cachedKey == null) {
            cachedKey = loadFromVault();
        }
        return cachedKey;
    }

    private PublicKey loadFromVault() {
        VaultResponse response =
                vaultTemplate.read("transit/export/public-key/" + signingKeyName);

        String pem = (String) ((Map<?, ?>) response.getData().get("keys"))
                .values()
                .iterator()
                .next();

        return parsePem(pem);
    }

    private PublicKey parsePem(String pem) {
        try {
            String content = pem
                    .replace("-----BEGIN PUBLIC KEY-----", "")
                    .replace("-----END PUBLIC KEY-----", "")
                    .replaceAll("\\s", "");

            byte[] decoded = Base64.getDecoder().decode(content);

            X509EncodedKeySpec spec = new X509EncodedKeySpec(decoded);
            return KeyFactory.getInstance("RSA").generatePublic(spec);

        } catch (Exception e) {
            throw new IllegalStateException("Failed to load public key", e);
        }
    }
}

