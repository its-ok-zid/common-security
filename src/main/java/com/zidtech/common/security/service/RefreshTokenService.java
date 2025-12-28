package com.zidtech.common.security.service;

import com.zidtech.common.security.model.RefreshToken;

import java.util.Optional;

public interface RefreshTokenService {

    RefreshToken issue(String username);

    Optional<RefreshToken> validate(String token);

    RefreshToken rotate(String token);

    void invalidateAll(String username);
}

