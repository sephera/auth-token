/*
 * Copyright (c) 2020  Hai Nguyen
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

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
		final AccessAuthenticationToken token = (AccessAuthenticationToken) authentication;
		try {
			final Algorithm algorithm = Algorithm.HMAC256(SECRET_KEY);
			JWTVerifier verifier = JWT.require(algorithm).withIssuer("auth-token").build();
			DecodedJWT jwt = verifier.verify((String) token.getCredentials());

			final Claim auClaim = jwt.getClaim("authority");
			final String[] authorities = auClaim.asArray(String.class);

			final Claim uriClaim = jwt.getClaim("uri");
			final String[] uris = uriClaim.asArray(String.class);

			return createSuccessAuthentication(token, authorities, uris);
		}
		catch (JWTVerificationException ex) {
			throw new BadCredentialsException("Invalid");
		}
	}

	private Authentication createSuccessAuthentication(AccessAuthenticationToken token, String[] authorities,
			String[] uris) {
		final Set<SimpleGrantedAuthority> au = Stream.of(authorities).map(SimpleGrantedAuthority::new)
				.collect(Collectors.toSet());
		final Set<String> uri = Stream.of(uris).collect(Collectors.toSet());
		final TokenUserDetail u = new TokenUserDetail(au, uri);
		return new AccessAuthenticationToken((String) token.getCredentials(), u, au);
	}

	@Override
	public boolean supports(Class<?> authentication) {
		return AccessAuthenticationToken.class.isAssignableFrom(authentication);
	}

}
