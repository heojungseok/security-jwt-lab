package com.example.securityjwtlab;

import org.springframework.stereotype.Component;

import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

@Component
public class RefreshTokenStore {
    //실무에선 여기 대신 DB/Redis + 해시 저장 + 만료/회전/기기별 관리 등

    // refreshToken -> userId (실습용 최소)
    private final Map<String, String> store = new ConcurrentHashMap<>();

    public void save(String refreshToken, String userId) {
        store.put(refreshToken, userId);
    }

    public boolean exists(String refreshToken) {
        return store.containsKey(refreshToken);
    }

    public String getUserId(String refreshToken) {
        return store.get(refreshToken);
    }

    public void revoke(String refreshToken) {
        store.remove(refreshToken);
    }
}
