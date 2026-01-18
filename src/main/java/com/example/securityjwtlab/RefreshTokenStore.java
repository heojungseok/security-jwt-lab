package com.example.securityjwtlab;

import org.springframework.stereotype.Component;

import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

@Component
public class RefreshTokenStore {

    // refreshToken -> userId
    private final Map<String, String> tokenToUser = new ConcurrentHashMap<>();

    // userId -> refreshTokens (선택: 사용자 단위 revoke 용)
    private final Map<String, Set<String>> userToTokens = new ConcurrentHashMap<>();

    public void save(String refreshToken, String userId) {
        tokenToUser.put(refreshToken, userId);
        userToTokens.computeIfAbsent(userId, k -> ConcurrentHashMap.newKeySet()).add(refreshToken);
    }

    public boolean exists(String refreshToken) {
        return tokenToUser.containsKey(refreshToken);
    }

    public String getUserId(String refreshToken) {
        return tokenToUser.get(refreshToken);
    }

    public void revoke(String refreshToken) {
        String userId = tokenToUser.remove(refreshToken);
        if (userId != null) {
            Set<String> tokens = userToTokens.get(userId);
            if (tokens != null) {
                tokens.remove(refreshToken);
                if (tokens.isEmpty()) {
                    userToTokens.remove(userId);
                }
            }
        }
    }

    public void revokeAllByUser(String userId) {
        Set<String> tokens = userToTokens.remove(userId);
        if (tokens != null) {
            for (String t : tokens) {
                tokenToUser.remove(t);
            }
        }
    }
}
