package com.example.securityjwtlab;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwtException;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.List;

@Slf4j
@Component
public class JwtAuthFilter extends OncePerRequestFilter {

    private final JwtProvider jwtProvider;

    public JwtAuthFilter(JwtProvider jwtProvider) {
        this.jwtProvider = jwtProvider;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                    HttpServletResponse response,
                                    FilterChain filterChain) throws ServletException, IOException {

        // 실습 단계에서는 "기존 인증 스킵" 로직은 빼는 게 디버깅이 쉬움 (나중에 운영 수준에서 최적화로 넣자)
        String authHeader = request.getHeader("Authorization");
        if (authHeader == null || !authHeader.startsWith("Bearer ")) {
            filterChain.doFilter(request, response);
            return;
        }

        String token = authHeader.substring(7);

        try {
            Claims claims = jwtProvider.parseAndValidate(token);
            jwtProvider.assertTokenType(claims, "access");

            String userId = claims.getSubject();

            @SuppressWarnings("unchecked")
            List<String> roles = (List<String>) claims.get("roles", List.class);

            var authorities = roles.stream()
                    .map(r -> r.startsWith("ROLE_") ? r : "ROLE_" + r)
                    .map(SimpleGrantedAuthority::new)
                    .toList();

            Authentication authentication =
                    new UsernamePasswordAuthenticationToken(userId, null, authorities);

            SecurityContextHolder.getContext().setAuthentication(authentication);

        } catch (JwtException | IllegalArgumentException e) {
            // 정책 Y: 유효하지 않으면 그냥 anonymous로 둠(체인 진행)
            // (원하면 여기서 로그만 남겨도 됨)
            log.warn("[JwtAuthFilter] token invalid: " + e.getClass().getSimpleName()
                    + " - " + e.getMessage());
        }

        filterChain.doFilter(request, response);
    }
}
