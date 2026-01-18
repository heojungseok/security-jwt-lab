package com.example.securityjwtlab;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jws;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import javax.crypto.SecretKey;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.Date;
import java.util.List;

@Component
public class JwtProvider {

    private final SecretKey key;
    private final long expMinutes;

    public JwtProvider(
            @Value("${jwt.secret}") String secret,
            @Value("${jwt.access-token-exp-minutes}") long expMinutes
    ) {
        this.key = Keys.hmacShaKeyFor(secret.getBytes(StandardCharsets.UTF_8));
        this.expMinutes = expMinutes;
    }

    public String createAccessToken(String userId, List<String> roles) {
        Instant now = Instant.now();
        Instant exp = now.plusSeconds(expMinutes * 60);

        return Jwts.builder()
                .subject(userId)                    // sub = userId
                .claim("roles", roles)              // roles payload
                .issuedAt(Date.from(now))
                .expiration(Date.from(exp))
                .signWith(key, Jwts.SIG.HS256)       // HS256 알고리즘 지정
                .compact();
    }

    /** 서명/만료 검증 포함 파싱. 실패 시 예외 발생 */
    public Claims parseAndValidate(String token) {
        Jws<Claims> jws = Jwts.parser()
                .verifyWith(key)
                .build()
                .parseSignedClaims(token);

        return jws.getPayload();
    }
}
