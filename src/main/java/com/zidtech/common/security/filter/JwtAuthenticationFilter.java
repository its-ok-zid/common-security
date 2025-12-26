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
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

@Slf4j
@RequiredArgsConstructor
public class JwtAuthenticationFilter extends OncePerRequestFilter {

    private final JwtUtil jwtUtil;
    private final SecurityUserService userService;
    private final SecurityProperties props;

    @Override
    protected void doFilterInternal(
            HttpServletRequest request,
            HttpServletResponse response,
            FilterChain chain
    ) throws ServletException, IOException {

        try {
            String token = resolveToken(request);

            if (token != null) {
                jwtUtil.validate(token);
                String username = jwtUtil.extractUsername(token);

                var user = userService.loadByUsername(username);

                var auth = new UsernamePasswordAuthenticationToken(
                        user, null, user.getAuthorities()
                );

                SecurityContextHolder.getContext().setAuthentication(auth);
            }

        } catch (Exception ex) {
            log.debug("JWT authentication failed: {}", ex.getMessage());
            SecurityContextHolder.clearContext();
        }

        chain.doFilter(request, response);
    }

    private String resolveToken(HttpServletRequest request) {
        String header = request.getHeader(props.getAuthHeader());
        if (header != null && header.startsWith("Bearer ")) {
            return header.substring(7);
        }

        if (request.getCookies() != null) {
            for (Cookie cookie : request.getCookies()) {
                if (props.getCookieName().equals(cookie.getName())) {
                    return cookie.getValue();
                }
            }
        }
        return null;
    }
}
