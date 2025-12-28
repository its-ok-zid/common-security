package com.zidtech.common.security.util;

import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletResponse;

public final class CookieUtil {

    private CookieUtil() {}

    public static void add(HttpServletResponse res, String name, String value, int maxAge) {
        Cookie c = new Cookie(name, value);
        c.setHttpOnly(true);
        c.setPath("/");
        c.setMaxAge(maxAge);
        res.addCookie(c);
    }

    public static void clear(HttpServletResponse res, String name) {
        Cookie c = new Cookie(name, null);
        c.setPath("/");
        c.setMaxAge(0);
        res.addCookie(c);
    }
}
