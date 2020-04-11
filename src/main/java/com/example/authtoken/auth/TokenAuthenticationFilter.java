package com.example.authtoken.auth;

import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.util.Assert;
import org.springframework.util.StringUtils;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

public class TokenAuthenticationFilter extends OncePerRequestFilter {

    private final AuthenticationEntryPoint authenticationEntryPoint;
    private final AuthenticationManager authenticationManager;

    public TokenAuthenticationFilter(AuthenticationEntryPoint authenticationEntryPoint, AuthenticationManager authenticationManager) {
        Assert.notNull(authenticationManager, "authenticationManager cannot be null");
        Assert.notNull(authenticationEntryPoint, "authenticationEntryPoint cannot be null");
        this.authenticationEntryPoint = authenticationEntryPoint;
        this.authenticationManager = authenticationManager;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain) throws ServletException, IOException {
        final boolean debug = this.logger.isDebugEnabled();

        try {
            final String token = request.getHeader("X-Auth-Token");


            if (debug) {
                this.logger.debug("Token Authentication Authorization header found for token '" + token + "'");
            }

            if (!StringUtils.isEmpty(token)) {
                AccessAuthenticationToken authRequest = new AccessAuthenticationToken(token, null);

                Authentication authResult = this.authenticationManager.authenticate(authRequest);

                if (debug) {
                    this.logger.debug("Authentication success: " + authResult);
                }

                SecurityContextHolder.getContext().setAuthentication(authResult);
            } else {
                throw new TokenNotFoundException("Not found token");
            }

        } catch (AuthenticationException failed) {
            SecurityContextHolder.clearContext();

            if (debug) {
                this.logger.debug("Authentication request for failed: " + failed);
            }

            this.authenticationEntryPoint.commence(request, response, failed);
            return;
        }

        chain.doFilter(request, response);
    }

}
