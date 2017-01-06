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
        String theToken = token.apply("user_id@server.com", "one role");
        assertNotNull(token);
        
        Jws<Claims> theClaims = claims.apply( theToken );
        assertNotNull(claims);
        assertEquals("user_id@server.com",  theClaims.getBody().getSubject());
        assertEquals("one role",            theClaims.getBody().get("roles"));
    }

    @Test(expected = ExpiredJwtException.class)
    public void assertTokenExpires() {
        String theToken = token.apply("user_id@server.com", "one role");
        assertNotNull(token);
        sleep( duration.get().getSeconds() * 1000 );
        claims.apply( theToken );
    }

    @Test
    public void assertcanRefreshAToken() {
        String theToken = token.apply("user_id@server.com", "one role");
        sleep( 4000 );
        String refreshedToken = refresh.apply( theToken );
        sleep( 4000 );
        claims.apply( refreshedToken );
        assertNotEquals(theToken, refreshedToken);
    }

    @Test(expected = ExpiredJwtException.class)
    public void assertCannotRefreshAnOutdatedToken() {
        String theToken = token.apply("user_id@server.com", "one role");
        assertNotNull(theToken);
        sleep( duration.get().getSeconds() * 1000 );
        refresh.apply( theToken );
    }

    private void sleep(final long time) {
        try { 
            currentThread().sleep( time ); 
        } catch (InterruptedException e) {
            throw new RuntimeException(e);
        }
    }
}
