package com.example.authtoken.auth;

import org.springframework.security.core.GrantedAuthority;

import java.util.Set;

public class TokenUserDetail {
    private Set<? extends GrantedAuthority> authorities;

    private Set<String> uri;

    public TokenUserDetail(Set<? extends GrantedAuthority> authorities, Set<String> uri) {
        this.authorities = authorities;
        this.uri = uri;
    }

    public Set<? extends GrantedAuthority> getAuthorities() {
        return authorities;
    }

    public Set<String> getUri() {
        return uri;
    }
}
