package com.example.securityjwtlab;

import org.springframework.security.core.Authentication;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class DemoController {

    @GetMapping("/public")
    public String pub() {
        return "public ok";
    }

    @GetMapping("/secure")
    public String secure(@AuthenticationPrincipal String userId) {
        return "secure ok, userId=" + userId;
    }

    @GetMapping("/admin")
    public String admin(@AuthenticationPrincipal String userId) {
        return "admin ok, userId=" + userId;
    }

    @GetMapping("/me")
    public String me() {
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        return "auth=" + (auth == null ? "null" : auth.toString());
    }
}
