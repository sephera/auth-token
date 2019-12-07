package com.example.authtoken.auth;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.exceptions.JWTVerificationException;
import com.auth0.jwt.interfaces.Claim;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.auth0.jwt.interfaces.JWTVerifier;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.stereotype.Service;

import java.util.Set;
import java.util.stream.Collectors;
import java.util.stream.Stream;

@Service
public class TokenAuthenticationProvider implements AuthenticationProvider {
    private static final String SECRET_KEY = "21ff04df-889b-4f4e-8930-cf0fad57df0f";

    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        final AccessToken token = (AccessToken) authentication;
        try {
            Algorithm algorithm = Algorithm.HMAC256(SECRET_KEY);
            JWTVerifier verifier = JWT.require(algorithm)
                    .withIssuer("auth-token")
                    .build();
            DecodedJWT jwt = verifier.verify((String) token.getCredentials());

            final Claim claim = jwt.getClaim("authority");
            final String[] authorities = claim.asArray(String.class);

            return createSuccessAuthentication(token, authorities);
        } catch (JWTVerificationException ex) {
            throw new BadCredentialsException("Invalid");
        }
    }

    private Authentication createSuccessAuthentication(AccessToken token, String[] authorities) {
        final Set<SimpleGrantedAuthority> au = Stream.of(authorities).map(SimpleGrantedAuthority::new).collect(Collectors.toSet());
        final TokenUserDetail u = new TokenUserDetail(au);
        return new AccessToken((String) token.getCredentials(), u, au);
    }

    @Override
    public boolean supports(Class<?> authentication) {
        return AccessToken.class.isAssignableFrom(authentication);
    }
}
