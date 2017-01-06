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
import java.time.Instant;
import java.util.function.BiFunction;
import java.util.function.Function;
import java.util.function.Supplier;

public class JwtHelper {
    static {
        KeyPair key = RsaProvider.generateKeyPair();
        PRIV = key.getPrivate();
        PUB  = key.getPublic();
        key  = null;
    }
    
    private JwtHelper() { /* private constructor to avoid instantiation */ }
    
    private static final Key      PRIV;
    private static final Key      PUB; 
    
    private static final String   JWT_ID   = "jwt id";
    private static final String   ISSUER   = "jomoespe issuer";
    private static final String   AUDIENCE = "jomoespe jwt test";
    private static final Duration DURATION = ofSeconds( 5 );

    public static Supplier<Duration> duration = () -> DURATION;
    
    private static final Function<Instant,Instant> expiration = (date) -> date.plus( duration.get() ) ;
    
    private static final Supplier<JwtBuilder> createBaseJwt    = ()     -> Jwts.builder()
            .signWith( RS256, PRIV )
            .setId( JWT_ID )
            .setIssuer( ISSUER )
            .setAudience( AUDIENCE )
            .setIssuedAt( from(now()) )
            .setNotBefore( from(now()) )
            .setExpiration( from( expiration.apply(now()) ) );
    
    public static BiFunction<String, String, String> token = (subject, role) -> {
        return createBaseJwt.get()
            .setSubject( subject )
            .claim("roles", role)
            .compact();
    };

    public static Function<String,Jws<Claims>> claims = (token) -> Jwts.parser()
            .setSigningKey( PUB )
            .parseClaimsJws( token );
    
    public static Function<String,String> refresh = (aToken) -> {
        Jws<Claims> theClaims = claims.apply( aToken );
        return token.apply( theClaims.getBody().getSubject(), theClaims.getBody().get("roles", String.class) );
    };
}
