package com.example.authtoken.auth;

import org.springframework.security.access.AccessDecisionVoter;
import org.springframework.security.access.ConfigAttribute;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.FilterInvocation;

import java.util.Collection;

public class UriAccessDecisionVoter implements AccessDecisionVoter<FilterInvocation> {
    @Override
    public boolean supports(ConfigAttribute attribute) {
        return true;
    }

    @Override
    public int vote(Authentication authentication, FilterInvocation fi, Collection<ConfigAttribute> attributes) {
        int rs = ACCESS_ABSTAIN;
        if (authentication instanceof AccessAuthenticationToken && authentication.getPrincipal() instanceof TokenUserDetail) {
            rs = ACCESS_DENIED;
            for (String uri : ((TokenUserDetail) authentication.getPrincipal()).getUri()) {
                if (fi.getRequestUrl().endsWith(uri)) {
                    rs = ACCESS_GRANTED;
                    break;
                }
            }
        }
        return rs;
    }

    @Override
    public boolean supports(Class clazz) {
        return FilterInvocation.class.isAssignableFrom(clazz);
    }
}
