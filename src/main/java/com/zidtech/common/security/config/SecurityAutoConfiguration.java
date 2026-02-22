package com.zidtech.common.security.config;

import com.zidtech.common.security.filter.JwtAuthFilter;
import com.zidtech.common.security.repository.RefreshTokenRepository;
import com.zidtech.common.security.repository.UserRepository;
import com.zidtech.common.security.service.CustomUserDetailsService;
import com.zidtech.common.security.service.RefreshTokenService;
import com.zidtech.common.security.util.CookieUtil;
import com.zidtech.common.security.util.JwtUtil;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.ComponentScan;
import org.springframework.scheduling.annotation.EnableScheduling;

@AutoConfiguration
@EnableScheduling
@ComponentScan("com.ecard.security")
@EnableConfigurationProperties(JwtProperties.class)
public class SecurityAutoConfiguration {

    @Bean
    @ConditionalOnMissingBean
    public JwtUtil jwtUtil(JwtProperties jwtProperties) {
        return new JwtUtil(jwtProperties);
    }

    @Bean
    @ConditionalOnMissingBean
    public CookieUtil cookieUtil(JwtProperties jwtProperties) {
        return new CookieUtil(jwtProperties);
    }

    @Bean
    @ConditionalOnMissingBean
    public CustomUserDetailsService customUserDetailsService(UserRepository userRepository) {
        return new CustomUserDetailsService(userRepository);
    }

    @Bean
    @ConditionalOnMissingBean
    public JwtAuthFilter jwtAuthFilter(JwtUtil jwtUtil,
                                       CustomUserDetailsService userDetailsService,
                                       CookieUtil cookieUtil) {
        return new JwtAuthFilter(jwtUtil, userDetailsService, cookieUtil);
    }

    @Bean
    @ConditionalOnMissingBean
    public RefreshTokenService refreshTokenService(RefreshTokenRepository refreshTokenRepository,
                                                   UserRepository userRepository,
                                                   JwtProperties jwtProperties) {
        return new RefreshTokenService(refreshTokenRepository, userRepository, jwtProperties);
    }
}
