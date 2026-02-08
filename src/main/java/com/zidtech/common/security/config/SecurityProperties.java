package com.zidtech.common.security.config;

import jakarta.annotation.PostConstruct;
import lombok.Data;
import org.springframework.boot.context.properties.ConfigurationProperties;

@Data
@ConfigurationProperties(prefix = "security.jwt")
public class SecurityProperties {

    private String secret;
    private long accessExpirationMs = 3600000;
    private long refreshExpirationMs = 604800000;
    private String accessCookie = "ACCESS_TOKEN";
    private String refreshCookie = "REFRESH_TOKEN";
    private boolean cookieSecure = true;
    private boolean cookieHttpOnly = true;
    private String cookiePath = "/";
    private String cookieSameSite = "Strict";
    private boolean defaultAuthenticated = false;

    @PostConstruct
    void validate() {
        if (secret == null || secret.length() < 32) {
            throw new IllegalStateException(
                    "security.jwt.secret must be at least 32 characters long"
            );
        }
        if (accessExpirationMs <= 0 || refreshExpirationMs <= 0) {
            throw new IllegalStateException("JWT expiration values must be positive");
        }
        if (accessCookie == null || accessCookie.isBlank() || refreshCookie == null || refreshCookie.isBlank()) {
            throw new IllegalStateException("Cookie names must not be blank");
        }
    }
}
