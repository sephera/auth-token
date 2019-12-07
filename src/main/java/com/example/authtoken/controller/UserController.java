package com.example.authtoken.controller;

import com.example.authtoken.auth.TokenUserDetail;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.annotation.Secured;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class UserController {
    @GetMapping("/user")
    public ResponseEntity<TokenUserDetail> getUser(@AuthenticationPrincipal TokenUserDetail ua) {
        return ResponseEntity.ok(ua);
    }

    @Secured("TESTER")
    @GetMapping("/tester")
    public ResponseEntity<TokenUserDetail> getTester(@AuthenticationPrincipal TokenUserDetail ua) {
        return ResponseEntity.ok(ua);
    }
}
