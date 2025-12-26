package com.zidtech.common.security.config;

import com.zidtech.common.security.filter.JwtAuthenticationFilter;
import com.zidtech.common.security.service.SecurityPolicyCustomizer;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

@Configuration
@EnableMethodSecurity
@RequiredArgsConstructor
public class SecurityFilterConfiguration {

    private final JwtAuthenticationFilter jwtFilter;
    private final ObjectProvider<SecurityPolicyCustomizer> policyCustomizer;

    @Bean
    SecurityFilterChain filterChain(HttpSecurity http) throws Exception {

        http
                .csrf(csrf -> csrf.disable())
                .sessionManagement(s -> s.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .addFilterBefore(jwtFilter, UsernamePasswordAuthenticationFilter.class);

        SecurityPolicyCustomizer customizer = policyCustomizer.getIfAvailable();
        if (customizer != null) {
            customizer.customize(http);
        } else {
            http.authorizeHttpRequests(auth -> auth.anyRequest().authenticated());
        }

        return http.build();
    }

    @Bean
    PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }
}
