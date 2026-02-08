package com.zidtech.common.security.filter;

import com.zidtech.common.security.config.SecurityProperties;
import com.zidtech.common.security.service.SecurityUserService;
import com.zidtech.common.security.util.JwtUtil;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpHeaders;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.List;
import java.util.Optional;

@RequiredArgsConstructor
public class JwtAuthenticationFilter extends OncePerRequestFilter {

    private static final String BEARER_PREFIX = "Bearer ";

    private final JwtUtil jwtUtil;
    private final SecurityUserService userService;
    private final SecurityProperties props;

    @Override
    protected void doFilterInternal(
            HttpServletRequest req,
            HttpServletResponse res,
            FilterChain chain
    ) throws ServletException, IOException {

        if (SecurityContextHolder.getContext().getAuthentication() == null) {
            Optional<String> tokenOpt = resolveToken(req);
            if (tokenOpt.isPresent()) {
                String token = tokenOpt.get();
                if (jwtUtil.isValid(token)) {
                    String username = jwtUtil.extractUsername(token);
                    List<SimpleGrantedAuthority> tokenAuthorities = jwtUtil.extractRoles(token)
                            .stream()
                            .map(SimpleGrantedAuthority::new)
                            .toList();

                    if (!tokenAuthorities.isEmpty()) {
                        SecurityContextHolder.getContext().setAuthentication(
                                new UsernamePasswordAuthenticationToken(username, null, tokenAuthorities)
                        );
                    } else {
                        var user = userService.loadByUsername(username);
                        SecurityContextHolder.getContext().setAuthentication(
                                new UsernamePasswordAuthenticationToken(user, null, user.getAuthorities())
                        );
                    }
                }
            }
        }

        chain.doFilter(req, res);
    }

    private Optional<String> resolveToken(HttpServletRequest request) {
        String authorization = request.getHeader(HttpHeaders.AUTHORIZATION);
        if (authorization != null && authorization.startsWith(BEARER_PREFIX)) {
            return Optional.of(authorization.substring(BEARER_PREFIX.length()).trim());
        }

        Cookie[] cookies = request.getCookies();
        if (cookies == null) {
            return Optional.empty();
        }

        for (Cookie cookie : cookies) {
            if (props.getAccessCookie().equals(cookie.getName())) {
                return Optional.ofNullable(cookie.getValue());
            }
        }
        return Optional.empty();
    }
}
