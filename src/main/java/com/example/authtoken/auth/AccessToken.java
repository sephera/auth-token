package com.example.authtoken.auth;

import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;

import java.util.Collection;

public class AccessToken extends AbstractAuthenticationToken {

    private String token;

    private TokenUserDetail principal;

    public AccessToken(String token, TokenUserDetail principal) {
        super(null);
        this.token = token;
        this.principal = principal;
        setAuthenticated(false);
    }

    public AccessToken(String token, TokenUserDetail principal, Collection<? extends GrantedAuthority> authorities) {
        super(authorities);
        this.token = token;
        this.principal = principal;
        setAuthenticated(true);
    }


    @Override
    public Object getCredentials() {
        return token;
    }

    @Override
    public Object getPrincipal() {
        return principal;
    }
}
