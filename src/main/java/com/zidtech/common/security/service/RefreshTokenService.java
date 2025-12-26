package com.zidtech.common.security.service;

import com.zidtech.common.security.model.RefreshToken;

import java.util.Optional;

public interface RefreshTokenService {

    RefreshToken create(String username);

    Optional<RefreshToken> find(String token);

    void invalidate(String token);

    void invalidateAll(String username);
}
