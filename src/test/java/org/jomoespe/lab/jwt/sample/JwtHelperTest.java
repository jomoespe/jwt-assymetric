package org.jomoespe.lab.jwt.sample;

import static org.jomoespe.lab.jwt.sample.JwtHelper.token;
import static org.jomoespe.lab.jwt.sample.JwtHelper.claims;
import static org.jomoespe.lab.jwt.sample.JwtHelper.expiration;

import static java.lang.Thread.currentThread;

import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertEquals;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jws;
import io.jsonwebtoken.ExpiredJwtException;

import org.junit.Test;

public class JwtHelperTest {
    @Test
    public void assertCanWorkWithToken() {
        String token = token("user_id@server.com", "Firstname Lastname");
        assertNotNull(token);
        
        Jws<Claims> claims = claims( token );
        assertNotNull(claims);
        assertEquals("user_id@server.com",  claims.getBody().getId());
        assertNotNull("Firstname Lastname", claims.getBody().getSubject());
    }

    @Test(expected = ExpiredJwtException.class)
    public void assertTokenExpires() {
        String token = token("user_id@server.com", "Firstname Lastname");
        assertNotNull(token);
        
        try {
            currentThread().sleep( expiration().getSeconds() * 1000 );
        } catch (InterruptedException e) {} 
        
        Jws<Claims> claims = claims( token );
    }
}
