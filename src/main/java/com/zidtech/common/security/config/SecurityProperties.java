package com.zidtech.common.security.config;

import lombok.Data;
import org.springframework.boot.context.properties.ConfigurationProperties;

@Data
@ConfigurationProperties(prefix = "security.jwt")
public class SecurityProperties {
    private String secret;
    private long expirationMs = 3600000;
    private String authHeader = "Authorization";
    private String cookieName = "ACCESS_TOKEN";
}
