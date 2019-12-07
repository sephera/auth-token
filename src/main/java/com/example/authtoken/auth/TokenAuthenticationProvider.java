package com.example.authtoken.auth;

import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.stereotype.Service;

@Service
public class TokenAuthenticationProvider implements AuthenticationProvider {
    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        final AccessToken token = (AccessToken) authentication;
        //TODO: check it with database or cache
        if (token.getCredentials().equals("xxx")) {
            return token;
        } else {
            throw new BadCredentialsException("Invalid");
        }
    }

    @Override
    public boolean supports(Class<?> authentication) {
        return AccessToken.class.isAssignableFrom(authentication);
    }
}
