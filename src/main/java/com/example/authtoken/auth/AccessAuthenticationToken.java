package com.example.authtoken.auth;

import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;

import java.util.Collection;

public class AccessAuthenticationToken extends AbstractAuthenticationToken {

    private String credentials;

    private TokenUserDetail principal;

    public AccessAuthenticationToken(String credentials, TokenUserDetail principal) {
        super(null);
        this.credentials = credentials;
        this.principal = principal;
        setAuthenticated(false);
    }

    public AccessAuthenticationToken(String credentials, TokenUserDetail principal, Collection<? extends GrantedAuthority> authorities) {
        super(authorities);
        this.credentials = credentials;
        this.principal = principal;
        setAuthenticated(true);
    }


    @Override
    public Object getCredentials() {
        return credentials;
    }

    @Override
    public Object getPrincipal() {
        return principal;
    }
}
