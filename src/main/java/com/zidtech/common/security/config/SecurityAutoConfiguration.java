package com.zidtech.common.security.config;

import com.zidtech.common.security.util.JwtUtil;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;

@AutoConfiguration
@EnableConfigurationProperties(SecurityProperties.class)
public class SecurityAutoConfiguration {

    @Bean
    public JwtUtil jwtUtil(SecurityProperties properties) {
        return new JwtUtil(properties);
    }
}
