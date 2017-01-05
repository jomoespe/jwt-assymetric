package org.jomoespe.lab.jwt.sample;

import static org.jomoespe.lab.jwt.sample.JwtHelper.token;
import static org.jomoespe.lab.jwt.sample.JwtHelper.claims;
import static org.jomoespe.lab.jwt.sample.JwtHelper.refresh;
import static org.jomoespe.lab.jwt.sample.JwtHelper.duration;

import static java.lang.Thread.currentThread;

import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotEquals;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jws;
import io.jsonwebtoken.ExpiredJwtException;

import org.junit.Test;

public class JwtHelperTest {
    @Test
    public void assertCanWorkWithToken() {
        String token = token("user_id@server.com", "one role");
        assertNotNull(token);
        
        Jws<Claims> claims = claims( token );
        assertNotNull(claims);
        assertEquals("user_id@server.com",  claims.getBody().getSubject());
        assertEquals("one role",            claims.getBody().get("roles"));
    }

    @Test(expected = ExpiredJwtException.class)
    public void assertTokenExpires() {
        String token = token("user_id@server.com", "one role");
        assertNotNull(token);
        
        try {
            currentThread().sleep( duration().getSeconds() * 1000 );
        } catch (InterruptedException e) {} 
        
        Jws<Claims> claims = claims( token );
    }

    @Test
    public void assertcanRefreshAToken() {
        String token = token("user_id@server.com", "one role");
        try { currentThread().sleep( 4000 ); } catch (InterruptedException e) {} 

        String refreshed = refresh( token );
        try { currentThread().sleep( 4000); } catch (InterruptedException e) {} 
        claims( refreshed );
        assertNotEquals(token, refreshed);
    }

    @Test(expected = ExpiredJwtException.class)
    public void assertCannotRefreshAnOutdatedToken() {
        String token = token("user_id@server.com", "one role");
        assertNotNull(token);
        
        try {
            currentThread().sleep( duration().getSeconds() * 1000 );
        } catch (InterruptedException e) {} 
        refresh( token );
    }

}
