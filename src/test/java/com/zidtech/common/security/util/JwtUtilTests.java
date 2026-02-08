package com.zidtech.common.security.util;

import com.zidtech.common.security.config.SecurityProperties;
import org.junit.jupiter.api.Test;
import org.springframework.test.util.ReflectionTestUtils;

import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

class JwtUtilTests {

    @Test
    void shouldGenerateAndParseTokenWithRoles() {
        SecurityProperties properties = new SecurityProperties();
        properties.setSecret("12345678901234567890123456789012");
        properties.setAccessExpirationMs(60_000L);
        properties.setRefreshExpirationMs(120_000L);
        properties.setAccessCookie("ACCESS_TOKEN");
        properties.setRefreshCookie("REFRESH_TOKEN");

        JwtUtil jwtUtil = new JwtUtil(properties);
        ReflectionTestUtils.invokeMethod(jwtUtil, "init");

        String token = jwtUtil.generateAccessToken("alice", List.of("ROLE_USER"));

        assertTrue(jwtUtil.isValid(token));
        assertEquals("alice", jwtUtil.extractUsername(token));
        assertEquals(List.of("ROLE_USER"), jwtUtil.extractRoles(token));
    }
}
