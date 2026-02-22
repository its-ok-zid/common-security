package com.zidtech.common.security.config;

import lombok.Data;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.stereotype.Component;

@Data
@Component
@ConfigurationProperties(prefix = "zidtech.security.jwt")
public class JwtProperties {

    /** Secret key - must be at least 256 bits (32 chars) */
    @Value("${zidtech.security.jwt.secret-key}")
    private String secretKey;

    /** Access token expiry in milliseconds. Default: 15 minutes */
    private long accessTokenExpiry = 15 * 60 * 1000L;

    /** Refresh token expiry in milliseconds. Default: 7 days */
    private long refreshTokenExpiry = 7 * 24 * 60 * 60 * 1000L;

    /** Cookie name for access token */
    private String accessTokenCookieName = "access_token";

    /** Cookie name for refresh token */
    private String refreshTokenCookieName = "refresh_token";
}