package com.zidtech.common.security.service;

import org.springframework.security.config.annotation.web.builders.HttpSecurity;

@FunctionalInterface
public interface SecurityPolicyCustomizer {
    void customize(HttpSecurity http) throws Exception;
}
