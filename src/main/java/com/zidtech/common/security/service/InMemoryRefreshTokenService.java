package com.zidtech.common.security.service;

import com.zidtech.common.security.config.SecurityProperties;
import com.zidtech.common.security.model.RefreshToken;

import java.security.SecureRandom;
import java.time.Instant;
import java.util.Base64;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;

public class InMemoryRefreshTokenService implements RefreshTokenService {

    private static final int REFRESH_TOKEN_BYTES = 64;

    private final SecurityProperties properties;
    private final SecureRandom secureRandom = new SecureRandom();
    private final Map<String, RefreshToken> byToken = new ConcurrentHashMap<>();

    public InMemoryRefreshTokenService(SecurityProperties properties) {
        this.properties = properties;
    }

    @Override
    public RefreshToken issue(String username) {
        RefreshToken refreshToken = buildToken(username);
        byToken.put(refreshToken.getToken(), refreshToken);
        return refreshToken;
    }

    @Override
    public Optional<RefreshToken> validate(String token) {
        RefreshToken refreshToken = byToken.get(token);
        if (refreshToken == null) {
            return Optional.empty();
        }
        if (refreshToken.getExpiry().isBefore(Instant.now())) {
            byToken.remove(token);
            return Optional.empty();
        }
        return Optional.of(refreshToken);
    }

    @Override
    public RefreshToken rotate(String token) {
        RefreshToken existing = validate(token)
                .orElseThrow(() -> new IllegalStateException("Invalid or expired refresh token"));

        byToken.remove(token);
        RefreshToken replacement = buildToken(existing.getUsername());
        byToken.put(replacement.getToken(), replacement);
        return replacement;
    }

    @Override
    public void invalidateAll(String username) {
        byToken.entrySet().removeIf(entry -> username.equals(entry.getValue().getUsername()));
    }

    private RefreshToken buildToken(String username) {
        Instant expiry = Instant.now().plusMillis(properties.getRefreshExpirationMs());
        return RefreshToken.builder()
                .token(newTokenValue())
                .username(username)
                .expiry(expiry)
                .build();
    }

    private String newTokenValue() {
        byte[] bytes = new byte[REFRESH_TOKEN_BYTES];
        secureRandom.nextBytes(bytes);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
    }
}
