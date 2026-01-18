package com.example.securityjwtlab;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;
import org.springframework.security.authentication.AnonymousAuthenticationToken;


import java.io.IOException;
import java.util.List;

@Component
@Slf4j
public class JwtAuthFilter extends OncePerRequestFilter {

    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                    HttpServletResponse response,
                                    FilterChain filterChain) throws ServletException, IOException {

        log.debug("[JwtAuthFilter] hit. uri=" + request.getRequestURI()
                + ", authHeader=" + request.getHeader("Authorization"));

        // 1) 이미 인증이 있으면 스킵, 익명 인증이 있으면 덮어씀
        Authentication existing = SecurityContextHolder.getContext().getAuthentication();
        if (existing != null && existing.isAuthenticated()) {
            filterChain.doFilter(request, response);
            return;
        }


        // 2) Authorization: Bearer <token>
        String authHeader = request.getHeader("Authorization");
        if (authHeader == null || !authHeader.startsWith("Bearer ")) {
            // 토큰이 없으면 anonymous로 두고 계속 진행
            filterChain.doFilter(request, response);
            return;
        }

        String token = authHeader.substring(7);
        log.debug("[JwtAuthFilter] token='" + token + "'");
        // 3) (학습용) 토큰 검증/파싱 흉내
        // valid-user  -> userId=100, ROLE_USER
        // valid-admin -> userId=200, ROLE_ADMIN
        String userId;
        List<GrantedAuthority> authorities;

        if ("valid-user".equals(token)) {
            userId = "100";
            authorities = List.of(new SimpleGrantedAuthority("ROLE_USER"));
        } else if ("valid-admin".equals(token)) {
            userId = "200";
            authorities = List.of(new SimpleGrantedAuthority("ROLE_ADMIN"));
        } else {
            // 정책 Y: 유효하지 않으면 그냥 anonymous로 둠
            filterChain.doFilter(request, response);
            return;
        }

        // 4) Authentication 생성 + SecurityContext에 저장
        Authentication authentication =
                new UsernamePasswordAuthenticationToken(userId, null, authorities);

        SecurityContextHolder.getContext().setAuthentication(authentication);
        log.debug("[JwtAuthFilter] set auth=" + SecurityContextHolder.getContext().getAuthentication());
        // 5) 다음 필터로 진행
        filterChain.doFilter(request, response);
    }
}
