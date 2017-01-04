package org.jomoespe.lab.jwt.sample;

import static org.jomoespe.lab.jwt.sample.JwtHelper.*;

import static org.junit.Assert.*;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jws;

import org.junit.Test;

public class JwtHelperTest {
    @Test
    public void assertCanWorkWithToken() {
        String token = token("user_id@server.com", "Firstname Lastname");
        assertNotNull(token);
        
        Jws<Claims> claims = claims(token);
        assertNotNull(claims);
        assertEquals("user_id@server.com",   claims.getBody().getId());
        assertNotNull("Firstname Lastname", claims.getBody().getSubject());
    }
}
