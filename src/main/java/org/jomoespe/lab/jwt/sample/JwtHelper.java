package org.jomoespe.lab.jwt.sample;

import static io.jsonwebtoken.SignatureAlgorithm.RS256;

import static java.time.Instant.now;
import static java.time.Duration.ofSeconds;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jws;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.impl.crypto.RsaProvider;

import java.security.Key;
import java.security.KeyPair;
import java.time.Duration;
import java.util.Date;

public class JwtHelper {
    static {
        KeyPair key = RsaProvider.generateKeyPair();
        PRIV = key.getPrivate();
        PUB  = key.getPublic();
        key  = null;
    }
    
    private JwtHelper() { /* private constructor to avoid instantiation */ }
    
    public static String token(final String id, final String subject) {
        return Jwts.builder()
            .signWith( RS256, PRIV )
            .setId( id )
            .setSubject( subject )
            .setExpiration( new Date(now().plus(EXPIRATION).toEpochMilli()) )
            .compact();
    }

    public static Jws<Claims> claims(final String token) {
        return Jwts.parser()
            .setSigningKey( PUB )
            .parseClaimsJws( token );
    }

    public static Duration expiration() {
        return EXPIRATION;
    }
    
    private static final long     DEFAULT_EXPIRATION = 5;  // in seconds
    private static final Duration EXPIRATION         = ofSeconds(DEFAULT_EXPIRATION);
    private static final Key      PRIV;
    private static final Key      PUB; 
}
