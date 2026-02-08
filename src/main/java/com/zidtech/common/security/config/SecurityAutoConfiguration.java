package com.zidtech.common.security.config;

import com.zidtech.common.security.filter.JwtAuthenticationFilter;
import com.zidtech.common.security.service.InMemoryRefreshTokenService;
import com.zidtech.common.security.service.RefreshTokenService;
import com.zidtech.common.security.service.SecurityPolicyCustomizer;
import com.zidtech.common.security.service.SecurityUserService;
import com.zidtech.common.security.util.JwtUtil;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import static org.springframework.security.config.http.SessionCreationPolicy.STATELESS;

@AutoConfiguration
@EnableMethodSecurity
@EnableConfigurationProperties(SecurityProperties.class)
public class SecurityAutoConfiguration {

    @Bean
    @ConditionalOnMissingBean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Bean
    @ConditionalOnMissingBean
    public JwtUtil jwtUtil(SecurityProperties props) {
        return new JwtUtil(props);
    }

    @Bean
    @ConditionalOnMissingBean
    public RefreshTokenService refreshTokenService(SecurityProperties props) {
        return new InMemoryRefreshTokenService(props);
    }

    @Bean
    @ConditionalOnMissingBean
    public JwtAuthenticationFilter jwtAuthenticationFilter(
            JwtUtil jwtUtil,
            SecurityUserService userService,
            SecurityProperties props) {
        return new JwtAuthenticationFilter(jwtUtil, userService, props);
    }

    @Bean(name = "securityFilterChain")
    @ConditionalOnMissingBean(name = "securityFilterChain")
    public SecurityFilterChain filterChain(
            HttpSecurity http,
            JwtAuthenticationFilter jwtFilter,
            SecurityProperties props,
            ObjectProvider<SecurityPolicyCustomizer> customizerProvider) throws Exception {

        http
                .csrf(csrf -> csrf.disable())
                .sessionManagement(s -> s.sessionCreationPolicy(STATELESS))
                .addFilterBefore(jwtFilter, UsernamePasswordAuthenticationFilter.class);

        if (props.isDefaultAuthenticated()) {
            http.authorizeHttpRequests(auth -> auth.anyRequest().authenticated());
        } else {
            http.authorizeHttpRequests(auth -> auth.anyRequest().permitAll());
        }

        SecurityPolicyCustomizer customizer = customizerProvider.getIfAvailable();
        if (customizer != null) {
            customizer.customize(http);
        }

        return http.build();
    }
}
