package com.zidtech.common.security.service;

import com.zidtech.common.security.config.SecurityProperties;
import com.zidtech.common.security.model.RefreshToken;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

class InMemoryRefreshTokenServiceTests {

    @Test
    void shouldIssueValidateAndRotateRefreshToken() {
        SecurityProperties properties = new SecurityProperties();
        properties.setSecret("12345678901234567890123456789012");
        properties.setRefreshExpirationMs(60_000L);

        InMemoryRefreshTokenService service = new InMemoryRefreshTokenService(properties);

        RefreshToken issued = service.issue("bob");
        assertTrue(service.validate(issued.getToken()).isPresent());

        RefreshToken rotated = service.rotate(issued.getToken());

        assertNotEquals(issued.getToken(), rotated.getToken());
        assertTrue(service.validate(rotated.getToken()).isPresent());
        assertTrue(service.validate(issued.getToken()).isEmpty());
    }
}
