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
    private final long accessExpMinutes;
    private final long refreshExpMinutes;

    public JwtProvider(
            @Value("${jwt.secret}") String secret,
            @Value("${jwt.access-token-exp-minutes}") long accessExpMinutes,
            @Value("${jwt.refresh-token-exp-minutes}") long refreshExpMinutes
    ) {
        this.key = Keys.hmacShaKeyFor(secret.getBytes(StandardCharsets.UTF_8));
        this.accessExpMinutes = accessExpMinutes;
        this.refreshExpMinutes = refreshExpMinutes;
    }

    public String createAccessToken(String userId, List<String> roles) {
        return createToken("access", userId, roles, accessExpMinutes);
    }

    public String createRefreshToken(String userId, List<String> roles) {
        return createToken("refresh", userId, roles, refreshExpMinutes);
    }

    private String createToken(String type, String userId, List<String> roles, long expMinutes) {
        Instant now = Instant.now();
        Instant exp = now.plusSeconds(expMinutes * 60);

        return Jwts.builder()
                .subject(userId)           // sub=userId
                .claim("roles", roles)     // roles=[...]
                .claim("typ", type)        // typ=access|refresh
                .issuedAt(Date.from(now))
                .expiration(Date.from(exp))
                // 알고리즘 명시(원하면 HS512로 바꿔도 됨)
                .signWith(key, Jwts.SIG.HS256)
                .compact();
    }

    public Claims parseAndValidate(String token) {
        Jws<Claims> jws = Jwts.parser()
                .verifyWith(key)
                .build()
                .parseSignedClaims(token);

        return jws.getPayload();
    }

    public void assertTokenType(Claims claims, String expectedType) {
        String typ = claims.get("typ", String.class);
        if (!expectedType.equals(typ)) {
            throw new IllegalArgumentException("Invalid token type. expected=" + expectedType + ", actual=" + typ);
        }
    }
}
