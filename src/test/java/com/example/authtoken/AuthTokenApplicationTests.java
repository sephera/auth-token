package com.example.authtoken;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.interfaces.Claim;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.auth0.jwt.interfaces.JWTVerifier;
import org.junit.Assert;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.junit4.SpringRunner;

@RunWith(SpringRunner.class)
@SpringBootTest
public class AuthTokenApplicationTests {

    @Test
    public void contextLoads() {
    }

    @Test
    public void createToken() {
        String secret = "21ff04df-889b-4f4e-8930-cf0fad57df0f";
        Algorithm algorithm = Algorithm.HMAC256(secret);
        String token = JWT.create()
                .withIssuer("auth-token")
                .withArrayClaim("authority", new String[]{"ADMIN", "USER"})
                .withArrayClaim("uri", new String[]{"/user", "/actuator/health"})
                .sign(algorithm);

        System.out.println(token);

        Assert.assertNotNull(token);
    }

    @Test
    public void verifyToken() {
        String token = "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJhdXRob3JpdHkiOlsiQURNSU4iLCJVU0VSIl0sImlzcyI6ImF1dGgtdG9rZW4iLCJ1cmkiOlsiL3VzZXIiLCIvYWN0dWF0b3IvaGVhbHRoIl19._BCoNG-wN93B3DvkCVXaPNOYe8GeXjX6fxfDuwCTdbE";
        String secret = "21ff04df-889b-4f4e-8930-cf0fad57df0f";
        Algorithm algorithm = Algorithm.HMAC256(secret);
        JWTVerifier verifier = JWT.require(algorithm)
                .withIssuer("auth-token")
                .build();
        DecodedJWT jwt = verifier.verify(token);
        final Claim claim = jwt.getClaim("authority");
        final String[] authorities = claim.asArray(String.class);
        System.out.println(authorities);


        Assert.assertNotNull(authorities);
    }
}
