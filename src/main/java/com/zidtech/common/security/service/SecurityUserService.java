package com.zidtech.common.security.service;

import com.zidtech.common.security.model.SecurityUser;

public interface SecurityUserService {
    SecurityUser loadByUsername(String username);
}
