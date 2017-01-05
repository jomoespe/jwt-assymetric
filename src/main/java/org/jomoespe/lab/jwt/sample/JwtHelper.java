package org.jomoespe.lab.jwt.sample;

import static io.jsonwebtoken.SignatureAlgorithm.RS256;

import static java.time.Instant.now;
import static java.time.Duration.ofSeconds;
import static java.util.Date.from;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jws;
import io.jsonwebtoken.JwtBuilder;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.impl.crypto.RsaProvider;

import java.security.Key;
import java.security.KeyPair;
import java.time.Duration;
import java.util.Date;
import java.util.function.Supplier;

public class JwtHelper {
    static {
        KeyPair key = RsaProvider.generateKeyPair();
        PRIV = key.getPrivate();
        PUB  = key.getPublic();
        key  = null;
    }
    
    private JwtHelper() { /* private constructor to avoid instantiation */ }
    
    public static String token(final String subject, final String role) {
        return baseJwt.get()
            .setSubject( subject )
            .claim("roles", role)
            .compact();
    }

    public static String refresh(final String token) {
        Jws<Claims> claims = claims( token );
        return token( claims.getBody().getSubject(), claims.getBody().get("roles", String.class) );
    }
    
    public static Jws<Claims> claims(final String token) {
        return Jwts.parser()
            .setSigningKey( PUB )
            .parseClaimsJws( token );
    }
    
    public static Duration duration() {
        return EXPIRATION;
    }

    private static final Key      PRIV;
    private static final Key      PUB; 
    
    private static final String   JWT_ID     = "jwt id";
    private static final String   ISSUER     = "jomoespe issuer";
    private static final String   AUDIENCE   = "jomoespe jwt test";
    private static final Duration EXPIRATION = ofSeconds( 5 );
    
    private static final Supplier<Date>       expiration = () -> from( now().plus( EXPIRATION ) );
    private static final Supplier<Date>       notBefore  = () -> from( now() );
    private static final Supplier<Date>       issuedAt   = () -> from( now() );
    private static final Supplier<JwtBuilder> baseJwt    = () -> Jwts.builder()
            .signWith( RS256, PRIV )
            .setId( JWT_ID )
            .setIssuer( ISSUER )
            .setAudience( AUDIENCE )
            .setExpiration( expiration.get() )
            .setNotBefore( notBefore.get() )
            .setIssuedAt( issuedAt.get() );
}
