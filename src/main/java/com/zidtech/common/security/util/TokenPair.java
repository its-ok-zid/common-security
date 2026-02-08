package com.zidtech.common.security.util;

import com.zidtech.common.security.model.JwtTokenPair;

/**
 * @deprecated use {@link JwtTokenPair}
 */
@Deprecated(forRemoval = true)
public class TokenPair extends JwtTokenPair {

    public TokenPair(String accessToken, String refreshToken) {
        super(accessToken, refreshToken);
    }
}
