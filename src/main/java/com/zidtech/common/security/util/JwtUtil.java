package com.zidtech.common.security.util;

import com.zidtech.common.security.config.SecurityProperties;
import com.zidtech.common.security.model.JwtTokenPair;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import jakarta.annotation.PostConstruct;
import lombok.RequiredArgsConstructor;

import javax.crypto.SecretKey;
import java.nio.charset.StandardCharsets;
import java.util.Collection;
import java.util.Date;
import java.util.List;

@RequiredArgsConstructor
public class JwtUtil {

    private static final String ROLES_CLAIM = "roles";

    private final SecurityProperties props;
    private SecretKey key;

    @PostConstruct
    void init() {
        key = Keys.hmacShaKeyFor(
                props.getSecret().getBytes(StandardCharsets.UTF_8)
        );
    }

    public JwtTokenPair generate(String username, String refreshToken) {
        return new JwtTokenPair(generateAccessToken(username), refreshToken);
    }

    public JwtTokenPair generate(String username, Collection<String> roles, String refreshToken) {
        return new JwtTokenPair(generateAccessToken(username, roles), refreshToken);
    }

    public String generateAccessToken(String username) {
        Date now = new Date();
        return Jwts.builder()
                .setSubject(username)
                .setIssuedAt(now)
                .setExpiration(new Date(now.getTime() + props.getAccessExpirationMs()))
                .signWith(key)
                .compact();
    }

    public String generateAccessToken(String username, Collection<String> roles) {
        Date now = new Date();
        return Jwts.builder()
                .setSubject(username)
                .claim(ROLES_CLAIM, roles)
                .setIssuedAt(now)
                .setExpiration(new Date(now.getTime() + props.getAccessExpirationMs()))
                .signWith(key)
                .compact();
    }

    public String extractUsername(String token) {
        return extractClaims(token).getSubject();
    }

    @SuppressWarnings("unchecked")
    public List<String> extractRoles(String token) {
        Object roles = extractClaims(token).get(ROLES_CLAIM);
        if (roles instanceof List<?> list) {
            return list.stream().map(String::valueOf).toList();
        }
        return List.of();
    }

    public Claims extractClaims(String token) {
        return Jwts.parserBuilder()
                .setSigningKey(key)
                .build()
                .parseClaimsJws(token)
                .getBody();
    }

    public boolean isValid(String token) {
        try {
            extractClaims(token);
            return true;
        } catch (RuntimeException e) {
            return false;
        }
    }
}
