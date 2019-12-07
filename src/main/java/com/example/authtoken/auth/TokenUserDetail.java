package com.example.authtoken.auth;

import org.springframework.security.core.GrantedAuthority;

import java.util.Set;

public class TokenUserDetail {
    private Set<? extends GrantedAuthority> authorities;

    public TokenUserDetail(Set<? extends GrantedAuthority> authorities) {
        this.authorities = authorities;
    }


    public Set<? extends GrantedAuthority> getAuthorities() {
        return authorities;
    }
}
