package com.zidtech.common.security.util;

import com.ecard.security.config.JwtProperties;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Component;

import java.util.Arrays;

@Component
@RequiredArgsConstructor
public class CookieUtil {

    private final JwtProperties jwtProperties;

    public void addAccessTokenCookie(HttpServletResponse response, String token) {
        addCookie(response,
                jwtProperties.getAccessTokenCookieName(),
                token,
                (int) (jwtProperties.getAccessTokenExpiry() / 1000));
    }

    public void addRefreshTokenCookie(HttpServletResponse response, String token) {
        addCookie(response,
                jwtProperties.getRefreshTokenCookieName(),
                token,
                (int) (jwtProperties.getRefreshTokenExpiry() / 1000));
    }

    public void clearAuthCookies(HttpServletResponse response) {
        clearCookie(response, jwtProperties.getAccessTokenCookieName());
        clearCookie(response, jwtProperties.getRefreshTokenCookieName());
    }

    public String extractTokenFromCookie(HttpServletRequest request) {
        if (request.getCookies() == null) return null;

        return Arrays.stream(request.getCookies())
                .filter(c -> c.getName().equals(jwtProperties.getAccessTokenCookieName()))
                .map(Cookie::getValue)
                .findFirst()
                .orElse(null);
    }

    public String extractRefreshTokenFromCookie(HttpServletRequest request) {
        if (request.getCookies() == null) return null;

        return Arrays.stream(request.getCookies())
                .filter(c -> c.getName().equals(jwtProperties.getRefreshTokenCookieName()))
                .map(Cookie::getValue)
                .findFirst()
                .orElse(null);
    }

    private void addCookie(HttpServletResponse response, String name, String value, int maxAge) {
        Cookie cookie = new Cookie(name, value);
        cookie.setHttpOnly(true);      // Not accessible via JavaScript (XSS protection)
        cookie.setSecure(true);        // HTTPS only
        cookie.setPath("/");
        cookie.setMaxAge(maxAge);
        // cookie.setAttribute("SameSite", "Strict"); // Uncomment for stricter CSRF protection
        response.addCookie(cookie);
    }

    private void clearCookie(HttpServletResponse response, String name) {
        Cookie cookie = new Cookie(name, null);
        cookie.setHttpOnly(true);
        cookie.setSecure(true);
        cookie.setPath("/");
        cookie.setMaxAge(0); // Immediately expire
        response.addCookie(cookie);
    }
}