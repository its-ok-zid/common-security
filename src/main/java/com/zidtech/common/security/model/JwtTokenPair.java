package com.zidtech.common.security.model;

import lombok.AllArgsConstructor;
import lombok.Getter;

@Getter
@AllArgsConstructor
public class JwtTokenPair {
    private final String accessToken;
    private final String refreshToken;
}
