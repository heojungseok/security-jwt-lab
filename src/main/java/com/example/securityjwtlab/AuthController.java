package com.example.securityjwtlab;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwtException;
import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.Map;

@RestController
@RequestMapping("/auth")
public class AuthController {

    private final JwtProvider jwtProvider;
    private final RefreshTokenStore refreshTokenStore;

    public AuthController(JwtProvider jwtProvider, RefreshTokenStore refreshTokenStore) {
        this.jwtProvider = jwtProvider;
        this.refreshTokenStore = refreshTokenStore;
    }

    // 예: /auth/login?user=|admin
    @GetMapping("/login")
    public Map<String, String> login(@RequestParam(defaultValue = "user") String user) {
        String userId;
        List<String> roles;

        if ("admin".equalsIgnoreCase(user)) {
            userId = "200";
            roles = List.of("ADMIN");
        } else {
            userId = "100";
            roles = List.of("USER");
        }

        String accessToken = jwtProvider.createAccessToken(userId, roles);
        String refreshToken = jwtProvider.createRefreshToken(userId, roles);

        refreshTokenStore.save(refreshToken, userId);

        return Map.of(
                "accessToken", accessToken,
                "refreshToken", refreshToken
        );
    }
    // refresh로 access 재발급
    @PostMapping("/refresh")
    public Map<String, String> refresh(@RequestBody Map<String, String> body) {
        System.out.println("[AuthController] /auth/refresh called");

        String refreshToken = body.get("refreshToken");
        if (refreshToken == null || refreshToken.isBlank()) {
            throw new IllegalArgumentException("Refresh token is required");
        }

        try {
            Claims claims = jwtProvider.parseAndValidate(refreshToken);
            jwtProvider.assertTokenType(claims, "refresh");

            // allowlist 체크(서버 저장된 refresh만 인정)
            if (!refreshTokenStore.exists(refreshToken)) {
                // 실무에서는 401/403으로 내리고 재로그인 유도
                throw new IllegalArgumentException("Refresh token revoked or unknown");
            }

            String userId = claims.getSubject();

            @SuppressWarnings("unchecked")
            List<String> roles = (List<String>) claims.get("roles", List.class);

            // (옵션) 회전(rotate): refresh 재발급 + 기존 revoke
            // ✅ 1) 기존 refresh 폐기(revoke)
            refreshTokenStore.revoke(refreshToken);
            // ✅ 2) 새 refresh 발급 + 저장
            String newRefreshToken = jwtProvider.createRefreshToken(userId, roles);
            refreshTokenStore.save(newRefreshToken, userId);
            // ✅ 3) 새 access 발급
            String newAccessToken = jwtProvider.createAccessToken(userId, roles);

            return Map.of(
                    "accessToken", newAccessToken,
                    "refreshToken", newRefreshToken
            );

        } catch (JwtException e) {
            throw new IllegalArgumentException("invalid refresh token", e);
        }
    }
}
