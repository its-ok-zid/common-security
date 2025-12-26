package com.zidtech.common.security.service;

public interface RefreshTokenService {
    void store(String username, String token);
    boolean validate(String token);
    void revoke(String username);
}
