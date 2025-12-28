package com.zidtech.common.security.controller;

import com.zidtech.common.security.model.RefreshToken;
import com.zidtech.common.security.service.RefreshTokenService;
import com.zidtech.common.security.service.SecurityUserService;
import com.zidtech.common.security.util.CookieUtil;
import com.zidtech.common.security.util.JwtUtil;
import com.zidtech.common.security.util.TokenPair;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.CookieValue;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.time.Instant;
import java.util.Map;

@RestController
@RequestMapping("/api/auth")
@RequiredArgsConstructor
public class AuthController {

    private final SecurityUserService userService;
    private final RefreshTokenService refreshTokenService;
    private final JwtUtil jwtUtil;

    /**
     * 🔐 LOGIN
     * - Validates credentials (delegated to SecurityUserService)
     * - Issues access + refresh token
     * - Stores refresh token (rotation-safe)
     * - Sets HttpOnly cookies
     */
    @PostMapping("/login")
    public ResponseEntity<?> login(
            @RequestBody Map<String, String> body,
            HttpServletResponse response) {

        String username = body.get("username");
        String password = body.get("password");

        var user = userService.loadByUsername(username);

        // Password validation MUST be handled inside service implementation
        if (user.getPassword() == null) {
            throw new BadCredentialsException("Invalid credentials");
        }

        RefreshToken refresh = refreshTokenService.issue(username);
        TokenPair pair = jwtUtil.generate(username, refresh.getToken());

        CookieUtil.add(response, "ACCESS_TOKEN", pair.getAccessToken(), 3600);
        CookieUtil.add(response, "REFRESH_TOKEN", pair.getRefreshToken(), 7 * 24 * 3600);

        return ResponseEntity.ok(Map.of(
                "accessToken", pair.getAccessToken(),
                "refreshToken", pair.getRefreshToken()
        ));
    }

    /**
     * 🔁 REFRESH TOKEN ROTATION
     */
    @PostMapping("/refresh")
    public ResponseEntity<?> refresh(
            @CookieValue("REFRESH_TOKEN") String refreshToken,
            HttpServletResponse response) {

        RefreshToken stored = refreshTokenService.validate(refreshToken)
                .orElseThrow(() -> new BadCredentialsException("Invalid refresh token"));

        if (stored.getExpiry().isBefore(Instant.now())) {
            refreshTokenService.rotate(refreshToken);
            throw new BadCredentialsException("Refresh token expired");
        }

        refreshTokenService.rotate(refreshToken);

        RefreshToken newToken = refreshTokenService.issue(stored.getUsername());
        TokenPair pair = jwtUtil.generate(stored.getUsername(), newToken.getToken());

        CookieUtil.add(response, "ACCESS_TOKEN", pair.getAccessToken(), 3600);
        CookieUtil.add(response, "REFRESH_TOKEN", pair.getRefreshToken(), 7 * 24 * 3600);

        return ResponseEntity.ok(Map.of(
                "accessToken", pair.getAccessToken()
        ));
    }

    /**
     * 🚪 LOGOUT
     */
    @PostMapping("/logout")
    public ResponseEntity<?> logout(
            Authentication auth,
            HttpServletResponse response) {

        if (auth != null) {
            refreshTokenService.invalidateAll(auth.getName());
        }

        CookieUtil.clear(response, "ACCESS_TOKEN");
        CookieUtil.clear(response, "REFRESH_TOKEN");

        return ResponseEntity.status(HttpStatus.OK)
                .body(Map.of("message", "Logged out successfully"));
    }
}
