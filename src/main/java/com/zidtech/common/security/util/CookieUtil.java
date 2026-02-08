package com.zidtech.common.security.util;

import jakarta.servlet.http.HttpServletResponse;
import org.springframework.http.HttpHeaders;
import org.springframework.http.ResponseCookie;

public final class CookieUtil {

    private CookieUtil() {
    }

    public static void add(HttpServletResponse res,
                           String name,
                           String value,
                           long maxAgeSeconds,
                           boolean secure,
                           boolean httpOnly,
                           String path,
                           String sameSite) {
        ResponseCookie cookie = ResponseCookie.from(name, value)
                .httpOnly(httpOnly)
                .secure(secure)
                .path(path)
                .maxAge(maxAgeSeconds)
                .sameSite(sameSite)
                .build();
        res.addHeader(HttpHeaders.SET_COOKIE, cookie.toString());
    }

    public static void clear(HttpServletResponse res,
                             String name,
                             boolean secure,
                             boolean httpOnly,
                             String path,
                             String sameSite) {
        ResponseCookie cookie = ResponseCookie.from(name, "")
                .httpOnly(httpOnly)
                .secure(secure)
                .path(path)
                .maxAge(0)
                .sameSite(sameSite)
                .build();
        res.addHeader(HttpHeaders.SET_COOKIE, cookie.toString());
    }
}
