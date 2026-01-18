package com.example.securityjwtlab;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwtException;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.http.ResponseCookie;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.time.Duration;
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

    // 예: /auth/login?user= user|admin
    @GetMapping("/login")
    public ResponseEntity<Map<String, String>> login(@RequestParam(defaultValue = "user") String user, HttpServletResponse response) {
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

        ResponseCookie cookie = ResponseCookie.from("refreshToken", refreshToken)
                .httpOnly(true)
                .secure(false)          // 로컬 http라서 false (https면 true)
                .sameSite("Lax")        // 실습은 Lax 권장
                .path("/auth")          // refresh 쿠키는 auth 경로에만
                .maxAge(Duration.ofMinutes(60))
                .build();

        response.addHeader("Set-Cookie", cookie.toString());

        return ResponseEntity.ok(Map.of("accessToken", accessToken));
    }
    // refresh로 access 재발급
    @PostMapping("/refresh")
    public ResponseEntity<Map<String, String>> refresh(@CookieValue(name = "refreshToken", required = false) String refreshToken, HttpServletResponse response) {

        if (refreshToken == null || refreshToken.isBlank()) {
            return ResponseEntity.status(401).body(Map.of("error", "missing refresh cookie"));
        }


        Claims claims = jwtProvider.parseAndValidate(refreshToken);
        jwtProvider.assertTokenType(claims, "refresh");

        // allowlist 체크(서버 저장된 refresh만 인정)
        if (!refreshTokenStore.exists(refreshToken)) {
            // 실무에서는 401/403으로 내리고 재로그인 유도
            return ResponseEntity.status(401).body(Map.of("error", "refresh revoked/unknown"));
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

        ResponseCookie cookie = ResponseCookie.from("refreshToken", newRefreshToken)
                .httpOnly(true)
                .secure(false)
                .sameSite("Lax")
                .path("/auth")
                .maxAge(Duration.ofMinutes(60))
                .build();

        response.addHeader("Set-Cookie", cookie.toString());


        return ResponseEntity.ok(Map.of("accessToken", newAccessToken));

    }

    @PostMapping("/logout")
    public ResponseEntity<Map<String, String>> logout(
            @CookieValue(name = "refreshToken", required = false) String refreshToken,
            HttpServletResponse response
    ) {
        // 서버 저장소에서 revoke (쿠키 없으면 그냥 스킵)
        if (refreshToken != null && !refreshToken.isBlank()) {
            refreshTokenStore.revoke(refreshToken);
        }

        // 쿠키 삭제: Max-Age=0 로 만료시키기
        ResponseCookie deleteCookie = ResponseCookie.from("refreshToken", "")
                .httpOnly(true)
                .secure(false)      // 로컬이면 false, https면 true
                .sameSite("Lax")
                .path("/auth")
                .maxAge(Duration.ZERO)
                .build();

        response.addHeader("Set-Cookie", deleteCookie.toString());

        return ResponseEntity.ok(Map.of("message", "logged out"));
    }
}
