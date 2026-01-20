# security-jwt-lab

Spring Security + JWT 입문 실습 레포지토리.  
**필수 개념(5개)**을 “개념 → 요구사항/설계 → 핵심 코드(하이라이트) → curl 검증”으로 **왕복**하며 이해하는 것을 목표로 한다.

> 이 README는 **전체 코드 덤프가 아니라**, 실습에서 의미가 있었던 **핵심 메소드/핵심 라인**만 남긴 문서다.  
> (package/import/보일러플레이트 제거)

---

## 목표

- Session vs JWT 차이를 “요청 처리 흐름” 관점에서 설명할 수 있다.
- JWT 구조(Header/Payload/Signature)를 “검증 관점”에서 설명할 수 있다.
- Spring Security Filter Chain에서 **인증이 만들어지는 위치**를 설명할 수 있다.
- SecurityContext/SecurityContextHolder(ThreadLocal)의 필요성과 주의점을 설명할 수 있다.
- `@AuthenticationPrincipal`이 주입되는 원천을 설명할 수 있다.
- Access 만료(exp) / Refresh 재발급 / Rotate(revoke+jti) / Logout(쿠키 삭제)까지 실습으로 검증한다.

---

## 범위(요구사항)

- `/public`: permitAll
- `/secure`: authenticated
- `/admin`: hasRole("ADMIN")
- Access Token: `Authorization: Bearer <token>` 헤더
- Refresh Token: `HttpOnly Cookie`
- Refresh: **회전(rotate)** — refresh 사용 시 기존 refresh revoke + 새 refresh 발급
- Logout: refresh revoke + 쿠키 삭제

---

## 설계 요약

### 요청 흐름
`Client → Security Filter Chain(JWT Filter) → Controller`

- Access Token이 있는 요청:
    - JWT 필터가 토큰을 검증하고 `Authentication`을 생성해 `SecurityContext`에 저장
    - 이후 `authenticated()` / `hasRole()` 규칙이 동작
- 토큰이 없거나 유효하지 않은 요청:
    - 필터는 **anonymous로 체인 진행**
    - 최종 접근 통제는 `authorizeHttpRequests` + exceptionHandling(401/403)에서 결정

### Token 정책
- Access: 짧은 만료(exp)
- Refresh: 쿠키 저장 + allowlist(store) 기반으로 revoke 가능
- Rotate: refresh 발급 시 `jti(UUID)`로 고유성 보장

---

## 필수 개념(체크리스트)

- [x] Session vs JWT 차이점
- [x] JWT Header/Payload/Signature 구조
- [x] Spring Security Filter Chain 개념
- [x] SecurityContext / SecurityContextHolder(ThreadLocal)
- [x] `@AuthenticationPrincipal` 원천 = `Authentication.principal`

---

## 핵심 코드(하이라이트)

> 아래는 **실습에서 핵심이었던 메소드/라인만** 발췌한 하이라이트다.

### 1) SecurityFilterChain — 인가 규칙 + 401/403 확정 + 필터 삽입

```java
@Bean
SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
    return http
        .csrf(csrf -> csrf.disable())
        .sessionManagement(sm -> sm.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
        .authorizeHttpRequests(auth -> auth
            .requestMatchers("/public").permitAll()
            .requestMatchers(HttpMethod.GET, "/auth/login").permitAll()

            // ✅ refresh/logout: 엔드포인트 접근은 permitAll로 두고
            //    내부에서 refresh 검증 실패 시 401로 처리
            .requestMatchers(HttpMethod.POST, "/auth/refresh", "/auth/logout").permitAll()

            // ✅ 권한 없으면 403
            .requestMatchers("/admin").hasRole("ADMIN")

            // ✅ 인증 없으면 401
            .anyRequest().authenticated()
        )
        .formLogin(form -> form.disable())
        .httpBasic(basic -> basic.disable())
        .exceptionHandling(ex -> ex
            .authenticationEntryPoint((req, res, e) -> {
                res.setStatus(401);
                res.setContentType(MediaType.TEXT_PLAIN_VALUE);
                res.setCharacterEncoding(StandardCharsets.UTF_8.name());
                res.getWriter().write("UNAUTHORIZED");
            })
            .accessDeniedHandler((req, res, e) -> {
                res.setStatus(403);
                res.setContentType(MediaType.TEXT_PLAIN_VALUE);
                res.setCharacterEncoding(StandardCharsets.UTF_8.name());
                res.getWriter().write("FORBIDDEN");
            })
        )
        // ✅ Controller 전에 인증 복원
        .addFilterBefore(jwtAuthFilter, UsernamePasswordAuthenticationFilter.class)
        .build();
}
```

---

### 2) JwtAuthFilter#doFilterInternal — “토큰 검증 → Authentication → SecurityContext”

```java
@Override
protected void doFilterInternal(HttpServletRequest request,
                                HttpServletResponse response,
                                FilterChain filterChain) throws ServletException, IOException {

    // ✅ 토큰 없으면 anonymous로 체인 진행
    String authHeader = request.getHeader("Authorization");
    if (authHeader == null || !authHeader.startsWith("Bearer ")) {
        filterChain.doFilter(request, response);
        return;
    }

    String token = authHeader.substring(7);

    try {
        // ✅ 서명/만료 검증
        Claims claims = jwtProvider.parseAndValidate(token);

        // ✅ typ=access 강제
        jwtProvider.assertTokenType(claims, "access");

        // ✅ principal = sub(userId)
        String userId = claims.getSubject();

        // ✅ roles -> ROLE_ 접두사 보정 -> GrantedAuthority
        List<String> roles = (List<String>) claims.get("roles", List.class);
        var authorities = roles.stream()
            .map(r -> r.startsWith("ROLE_") ? r : "ROLE_" + r)
            .map(SimpleGrantedAuthority::new)
            .toList();

        Authentication authentication =
            new UsernamePasswordAuthenticationToken(userId, null, authorities);

        // ✅ 이 한 줄이 /secure 통과 여부를 결정
        SecurityContextHolder.getContext().setAuthentication(authentication);

    } catch (JwtException | IllegalArgumentException e) {
        // ✅ 정책: invalid면 anonymous 유지(체인 진행)
        log.warn("[JwtAuthFilter] token invalid: {} - {}", e.getClass().getSimpleName(), e.getMessage());
    }

    filterChain.doFilter(request, response);
}
```

---

### 3) JwtProvider — typ 분리 + refresh jti + parseAndValidate

```java
private String createToken(String type, String userId, List<String> roles, long expMinutes) {
    Instant now = Instant.now();
    Instant exp = now.plusSeconds(expMinutes * 60);

    JwtBuilder builder = Jwts.builder()
        .subject(userId)        // ✅ sub
        .claim("roles", roles)  // ✅ roles
        .claim("typ", type)     // ✅ access|refresh
        .issuedAt(Date.from(now))
        .expiration(Date.from(exp));

    // ✅ refresh는 rotate 시 고유해야 함 → jti(UUID)
    if ("refresh".equals(type)) {
        builder.id(UUID.randomUUID().toString());
    }

    return builder.signWith(key, Jwts.SIG.HS256).compact();
}

public Claims parseAndValidate(String token) {
    // ✅ 서명/만료 검증의 핵심(실패 시 JwtException)
    return Jwts.parser()
        .verifyWith(key)
        .build()
        .parseSignedClaims(token)
        .getPayload();
}

public void assertTokenType(Claims claims, String expectedType) {
    String typ = claims.get("typ", String.class);
    if (!expectedType.equals(typ)) {
        throw new IllegalArgumentException("Invalid token type. expected=" + expectedType + ", actual=" + typ);
    }
}
```

---

### 4) AuthController#refresh — 쿠키 refresh + allowlist + rotate + access 재발급

```java
@PostMapping("/refresh")
public ResponseEntity<Map<String, String>> refresh(
    @CookieValue(name = "refreshToken", required = false) String refreshToken,
    HttpServletResponse response
) {
    if (refreshToken == null || refreshToken.isBlank()) {
        return ResponseEntity.status(401).body(Map.of("error", "missing refresh cookie"));
    }

    Claims claims = jwtProvider.parseAndValidate(refreshToken);
    jwtProvider.assertTokenType(claims, "refresh");

    // ✅ allowlist 없으면(이미 revoke/unknown) 401
    if (!refreshTokenStore.exists(refreshToken)) {
        return ResponseEntity.status(401).body(Map.of("error", "refresh revoked/unknown"));
    }

    String userId = claims.getSubject();
    List<String> roles = (List<String>) claims.get("roles", List.class);

    // ✅ rotate: 기존 refresh revoke → 새 refresh 발급/저장
    refreshTokenStore.revoke(refreshToken);
    String newRefreshToken = jwtProvider.createRefreshToken(userId, roles);
    refreshTokenStore.save(newRefreshToken, userId);

    // ✅ 새 access 발급
    String newAccessToken = jwtProvider.createAccessToken(userId, roles);

    // ✅ 쿠키 갱신(HttpOnly + Path=/auth)
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
```

---

### 5) AuthController#logout — revoke + 쿠키 삭제(path 일치)

```java
@PostMapping("/logout")
public ResponseEntity<Map<String, String>> logout(
    @CookieValue(name = "refreshToken", required = false) String refreshToken,
    HttpServletResponse response
) {
    if (refreshToken != null && !refreshToken.isBlank()) {
        refreshTokenStore.revoke(refreshToken);
    }

    // ✅ 삭제 쿠키의 path는 발급 때와 동일해야 함(/auth)
    ResponseCookie deleteCookie = ResponseCookie.from("refreshToken", "")
        .httpOnly(true)
        .secure(false)
        .sameSite("Lax")
        .path("/auth")
        .maxAge(Duration.ZERO)
        .build();

    response.addHeader("Set-Cookie", deleteCookie.toString());

    return ResponseEntity.ok(Map.of("message", "logged out"));
}
```

---

## 실행/검증(curl)

### 1) /secure: 토큰 없으면 401, 있으면 200
```bash
curl -i http://localhost:8080/secure
# 기대: 401

curl -s "http://localhost:8080/auth/login?user=user"
# 응답 accessToken 복사

curl -i -H "Authorization: Bearer <accessToken>" http://localhost:8080/secure
# 기대: 200
```

### 2) /admin: 권한 없으면 403
```bash
curl -i -H "Authorization: Bearer <ROLE_USER accessToken>" http://localhost:8080/admin
# 기대: 403
```

### 3) refresh(쿠키) + rotate + logout
```bash
# 로그인: refresh 쿠키 저장
curl -i -c cookies.txt "http://localhost:8080/auth/login?user=user"

# refresh: 쿠키 기반 재발급(쿠키 갱신 + accessToken 새로 반환)
curl -i -b cookies.txt -c cookies.txt -X POST http://localhost:8080/auth/refresh

# logout: revoke + 쿠키 삭제
curl -i -b cookies.txt -c cookies.txt -X POST http://localhost:8080/auth/logout

# logout 후 refresh는 실패(401) 기대
curl -i -b cookies.txt -c cookies.txt -X POST http://localhost:8080/auth/refresh
```

---

## 트러블슈팅 & 실무 포인트

### 1) 401 vs 403 (원인 기준)
- **401**: 인증이 없음/유효하지 않음(토큰 없음/만료/서명 오류/refresh revoke)
- **403**: 인증은 됐지만 권한 부족(`/admin`에 ADMIN 없음)

### 2) refresh rotate 했는데 토큰이 같아 보이는 문제
- 같은 초(iat) + 동일 sub/roles/typ/exp 조합이면 “같은 문자열처럼” 보일 수 있음
- refresh에 `jti(UUID)`를 넣어 **발급마다 고유성 확보**

### 3) 쿠키 삭제가 안 될 때
- 삭제 쿠키의 `path`는 발급 쿠키의 `path`와 **반드시 동일**
- 운영에서는 `Secure=true(https)`/도메인 설정도 정합성 필요

### 4) refresh 예외 처리(실무 권장)
`parseAndValidate()`는 만료/서명 오류에서 예외 발생 가능 → 401로 안정적으로 반환 권장.

```java
try {
    Claims claims = jwtProvider.parseAndValidate(refreshToken);
    jwtProvider.assertTokenType(claims, "refresh");
} catch (JwtException | IllegalArgumentException e) {
    return ResponseEntity.status(401).body(Map.of("error", "invalid refresh token"));
}
```