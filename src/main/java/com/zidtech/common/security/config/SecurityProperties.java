package com.zidtech.common.security.config;

import jakarta.annotation.PostConstruct;
import lombok.Data;
import org.springframework.boot.context.properties.ConfigurationProperties;

@Data
@ConfigurationProperties(prefix = "security.jwt")
public class SecurityProperties {

    private String secret;
    private long accessTokenExpirationMs = 3600000;      // 1 hour
    private long refreshTokenExpirationMs = 604800000;   // 7 days
    private String authHeader = "Authorization";
    private String cookieName = "ACCESS_TOKEN";


@PostConstruct
    void validate() {
        if (secret == null || secret.length() < 32) {
            throw new IllegalStateException(
                    "security.jwt.secret must be at least 32 characters long"
            );
        }
    }
}
