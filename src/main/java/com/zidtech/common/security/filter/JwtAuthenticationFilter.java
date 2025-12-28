package com.zidtech.common.security.filter;

import com.zidtech.common.security.config.SecurityProperties;
import com.zidtech.common.security.service.SecurityUserService;
import com.zidtech.common.security.util.JwtUtil;
import jakarta.servlet.FilterChain;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;

@RequiredArgsConstructor
public class JwtAuthenticationFilter extends OncePerRequestFilter {

    private final JwtUtil jwtUtil;
    private final SecurityUserService userService;
    private final SecurityProperties props;

    @Override
    protected void doFilterInternal(
            HttpServletRequest req,
            HttpServletResponse res,
            FilterChain chain) {

        try {
            if (req.getCookies() != null) {
                for (Cookie c : req.getCookies()) {
                    if (props.getAccessCookie().equals(c.getName())) {
                        String username = jwtUtil.extractUsername(c.getValue());
                        var user = userService.loadByUsername(username);
                        SecurityContextHolder.getContext().setAuthentication(
                                new UsernamePasswordAuthenticationToken(
                                        user, null, user.getAuthorities()));
                    }
                }
            }
        } catch (Exception ignored) {}

        try { chain.doFilter(req, res); }
        catch (Exception e) { throw new RuntimeException(e); }
    }
}
