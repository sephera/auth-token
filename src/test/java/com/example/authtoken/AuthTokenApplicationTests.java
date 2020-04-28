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

package com.example.authtoken;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.interfaces.Claim;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.auth0.jwt.interfaces.JWTVerifier;
import org.junit.Assert;
import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.SpringBootTest;

import java.util.Arrays;

@SpringBootTest
public class AuthTokenApplicationTests {

	@Test
	public void contextLoads() {
	}

	@Test
	public void createToken() {
		String secret = "21ff04df-889b-4f4e-8930-cf0fad57df0f";
		Algorithm algorithm = Algorithm.HMAC256(secret);
		String token = JWT.create().withIssuer("auth-token")
				.withArrayClaim("authority", new String[] { "ADMIN", "USER" })
				.withArrayClaim("uri", new String[] { "/user", "/actuator/health" }).sign(algorithm);

		System.out.println(token);

		Assert.assertNotNull(token);
	}

	@Test
	public void verifyToken() {
		String token = "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJhdXRob3JpdHkiOlsiQURNSU4iLCJVU0VSIl0sImlzcyI6ImF1dGgtdG9rZW4iLCJ1cmkiOlsiL3VzZXIiLCIvYWN0dWF0b3IvaGVhbHRoIl19._BCoNG-wN93B3DvkCVXaPNOYe8GeXjX6fxfDuwCTdbE";
		String secret = "21ff04df-889b-4f4e-8930-cf0fad57df0f";
		Algorithm algorithm = Algorithm.HMAC256(secret);
		JWTVerifier verifier = JWT.require(algorithm).withIssuer("auth-token").build();
		DecodedJWT jwt = verifier.verify(token);
		final Claim claim = jwt.getClaim("authority");
		final String[] authorities = claim.asArray(String.class);
		System.out.println(Arrays.toString(authorities));

		Assert.assertNotNull(authorities);
	}

}
