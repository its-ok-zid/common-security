# 🔐 common-security
Reusable Spring Security + JWT starter for Spring Boot microservices.

## Overview
`common-security` is a shared security mechanism library. It provides JWT validation, Spring Security context setup, stateless defaults, and secure cookie helpers so each microservice can avoid duplicating core security wiring.

> This library provides **security mechanism**, while each microservice keeps **security policy**.

## Features
- Spring Boot auto-configuration (`SecurityFilterChain`, JWT filter, BCrypt `PasswordEncoder`)
- JWT validation from both:
  - `Authorization: Bearer <token>` header
  - access-token cookie (`security.jwt.access-cookie`)
- Strong property validation for JWT secret and expirations
- Cookie helper with `HttpOnly`, `Secure`, `SameSite`, and path control
- Extension points:
  - `SecurityUserService`
  - `RefreshTokenService`
  - `SecurityPolicyCustomizer`

## Maven dependency
```xml
<dependency>
    <groupId>com.zidtech.security</groupId>
    <artifactId>common-security</artifactId>
    <version>1.0.4</version>
</dependency>
```

## Required properties
```properties
security.jwt.secret=replace-with-32-plus-char-secret-key
```

## Optional properties
```properties
security.jwt.access-expiration-ms=3600000
security.jwt.refresh-expiration-ms=604800000
security.jwt.access-cookie=ACCESS_TOKEN
security.jwt.refresh-cookie=REFRESH_TOKEN
security.jwt.cookie-secure=true
security.jwt.cookie-http-only=true
security.jwt.cookie-path=/
security.jwt.cookie-same-site=Strict
security.jwt.default-authenticated=false

# disabled by default to avoid overriding host app error contracts
security.common.global-exception-handler-enabled=false
```

## Consumer integration
Provide an implementation for `SecurityUserService`:

```java
@Service
public class UserPrincipalService implements SecurityUserService {
    @Override
    public SecurityUser loadByUsername(String username) {
        // load user from your service/repo and map authorities
        return SecurityUser.builder()
                .id(1L)
                .username(username)
                .password("N/A")
                .authorities(List.of(new SimpleGrantedAuthority("ROLE_USER")))
                .build();
    }
}
```

### Optional policy customization
Use `SecurityPolicyCustomizer` to define service-specific authorization rules:

```java
@Bean
SecurityPolicyCustomizer securityPolicyCustomizer() {
    return http -> http.authorizeHttpRequests(auth -> auth
            .requestMatchers("/actuator/health", "/auth/**").permitAll()
            .anyRequest().authenticated());
}
```

## Notes
- Refresh token persistence/rotation storage stays service-owned by design.
- `TokenPair` is deprecated; use `JwtTokenPair`.
