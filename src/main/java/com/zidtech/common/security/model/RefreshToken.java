package com.zidtech.common.security.model;

import lombok.Builder;
import lombok.Getter;

import java.time.Instant;

@Getter
@Builder
public class RefreshToken {

    private final String token;
    private final String username;
    private final Instant expiry;
}
