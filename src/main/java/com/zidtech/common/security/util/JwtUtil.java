package com.zidtech.common.security.util;

import com.zidtech.common.security.config.SecurityProperties;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import jakarta.annotation.PostConstruct;
import lombok.RequiredArgsConstructor;
import javax.crypto.SecretKey;
import java.nio.charset.StandardCharsets;
import java.util.Date;

@RequiredArgsConstructor
public class JwtUtil {

    private final SecurityProperties props;
    private SecretKey key;

    @PostConstruct
    void init() {
        key = Keys.hmacShaKeyFor(
                props.getSecret().getBytes(StandardCharsets.UTF_8)
        );
    }

    public TokenPair generate(String username, String refreshToken) {
        Date now = new Date();

        String access = Jwts.builder()
                .setSubject(username)
                .setIssuedAt(now)
                .setExpiration(
                        new Date(now.getTime() + props.getExpirationMs())
                )
                .signWith(key)
                .compact();

        return new TokenPair(access, refreshToken);
    }

    public String extractUsername(String token) {
        return Jwts.parserBuilder()
                .setSigningKey(key)
                .build()
                .parseClaimsJws(token)
                .getBody()
                .getSubject();
    }

    public boolean isValid(String token) {
        try {
            Jwts.parserBuilder()
                    .setSigningKey(key)
                    .build()
                    .parseClaimsJws(token);
            return true;
        } catch (Exception e) {
            return false;
        }
    }
}
