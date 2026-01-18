package com.example.securityjwtlab;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;
import java.util.Map;

@RestController
public class AuthController {

    private final JwtProvider jwtProvider;

    public AuthController(JwtProvider jwtProvider) {
        this.jwtProvider = jwtProvider;
    }

    // 예: /auth/login?user=user  또는 /auth/login?user=admin
    @GetMapping("/auth/login")
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
        return Map.of("accessToken", accessToken);
    }
}
