package com.zidtech.common.security.util;

import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpServletResponse;

import static org.junit.jupiter.api.Assertions.assertTrue;

class CookieUtilTests {

    @Test
    void shouldSetCookieHeadersForAddAndClear() {
        MockHttpServletResponse response = new MockHttpServletResponse();

        CookieUtil.add(response, "ACCESS_TOKEN", "abc", 3600, true, true, "/", "Strict");
        CookieUtil.clear(response, "ACCESS_TOKEN", true, true, "/", "Strict");

        String headers = String.join("\n", response.getHeaders("Set-Cookie"));

        assertTrue(headers.contains("ACCESS_TOKEN=abc"));
        assertTrue(headers.contains("Max-Age=3600"));
        assertTrue(headers.contains("SameSite=Strict"));
        assertTrue(headers.contains("ACCESS_TOKEN="));
        assertTrue(headers.contains("Max-Age=0"));
    }
}
