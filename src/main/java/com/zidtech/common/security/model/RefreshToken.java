package com.zidtech.common.security.model;

import lombok.Builder;
import lombok.Data;

import java.time.Instant;

@Data
@Builder
public class RefreshToken {
    private String token;
    private String username;
    private Instant expiry;
}
